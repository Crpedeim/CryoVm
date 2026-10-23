// Package s3 is a small client for S3-compatible object stores (SeaweedFS,
// MinIO, AWS S3): put, get, delete and list objects, and make a bucket.
// It speaks path-style URLs (http://host:port/bucket/key) and signs every
// request with AWS Signature Version 4.
//
// SigV4, in one paragraph: the request is reduced to a "canonical request"
// (method, path, sorted query, sorted lowercase headers, the body's
// SHA-256), which is hashed into a "string to sign" with the time and a
// scope (date/region/service). A signing key is derived from the secret by
// a chain of HMACs over the date, region and service, and the signature is
// the HMAC of the string to sign. The server repeats all of it with its own
// copy of the secret; one differing byte anywhere and the request is
// refused. The secret itself never crosses the network.
package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Client talks to one S3-compatible endpoint.
type Client struct {
	Endpoint  string // e.g. http://127.0.0.1:8333
	Region    string // default us-east-1 (SeaweedFS and MinIO accept it)
	AccessKey string
	SecretKey string
	HTTP      *http.Client
	Now       func() time.Time // for tests; default time.Now
}

// ErrNotFound is a missing object or bucket.
var ErrNotFound = errors.New("s3: not found")

// emptyHash is the SHA-256 of an empty body.
const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Object is one entry of a listing.
type Object struct {
	Key  string
	Size int64
}

func (c *Client) region() string {
	if c.Region == "" {
		return "us-east-1"
	}
	return c.Region
}

func (c *Client) do(ctx context.Context, method, bucket, key string, query url.Values, body io.Reader, size int64, bodyHash string) (*http.Response, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("s3: endpoint: %w", err)
	}
	u.Path = "/" + bucket
	if key != "" {
		u.Path += "/" + key
	}
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	if bodyHash == "" {
		bodyHash = emptyHash
	}
	c.Sign(req, bodyHash)
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	return hc.Do(req)
}

// Sign adds SigV4 headers to req; bodyHash is the hex SHA-256 of its body.
func (c *Client) Sign(req *http.Request, bodyHash string) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	t := now().UTC()
	amzDate, day := t.Format("20060102T150405Z"), t.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", bodyHash)
	host := req.URL.Host

	// Canonical headers: host and every x-amz-* header, plus any already
	// set ones the request carries (Range, say), lowercased and sorted.
	headers := map[string]string{"host": host}
	for name, vals := range req.Header {
		headers[strings.ToLower(name)] = strings.TrimSpace(strings.Join(vals, ","))
	}
	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		canonHeaders.WriteString(n + ":" + headers[n] + "\n")
	}
	signed := strings.Join(names, ";")

	canonical := strings.Join([]string{
		req.Method,
		escapePath(req.URL.EscapedPath()),
		canonicalQuery(req.URL.Query()),
		canonHeaders.String(),
		signed,
		bodyHash,
	}, "\n")
	scope := day + "/" + c.region() + "/s3/aws4_request"
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])

	key := hmacSHA256([]byte("AWS4"+c.SecretKey), day)
	key = hmacSHA256(key, c.region())
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKey, scope, signed, sig))
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// escapePath re-escapes a path the SigV4 way: everything but unreserved
// characters and '/', each segment encoded once.
func escapePath(p string) string {
	unescaped, err := url.PathUnescape(p)
	if err != nil {
		unescaped = p
	}
	if unescaped == "" {
		return "/"
	}
	var b strings.Builder
	for _, r := range []byte(unescaped) {
		if r == '/' || unreserved(r) {
			b.WriteByte(r)
		} else {
			fmt.Fprintf(&b, "%%%02X", r)
		}
	}
	return b.String()
}

func unreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~'
}

func encodeStrict(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if unreserved(s[i]) {
			b.WriteByte(s[i])
		} else {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	var parts []string
	for k, vs := range q {
		for _, v := range vs {
			parts = append(parts, encodeStrict(k)+"="+encodeStrict(v))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// apiError reads an S3 error response.
func apiError(op string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	_ = xml.Unmarshal(body, &e)
	if resp.StatusCode == http.StatusNotFound || e.Code == "NoSuchKey" || e.Code == "NoSuchBucket" {
		return fmt.Errorf("%w: %s: %s", ErrNotFound, op, e.Code)
	}
	if e.Code == "" {
		e.Code = resp.Status
	}
	return fmt.Errorf("s3: %s: %s %s", op, e.Code, e.Message)
}

// MakeBucket creates a bucket; one that already exists is fine.
func (c *Client) MakeBucket(ctx context.Context, bucket string) error {
	resp, err := c.do(ctx, http.MethodPut, bucket, "", nil, nil, 0, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	err = apiError("make bucket "+bucket, resp)
	if strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") || strings.Contains(err.Error(), "BucketAlreadyExists") {
		return nil
	}
	return err
}

// Put stores body (size bytes, whose hex SHA-256 is sha) at key. The hash
// is signed, so the server checks the body against it.
func (c *Client) Put(ctx context.Context, bucket, key string, body io.Reader, size int64, sha string) error {
	resp, err := c.do(ctx, http.MethodPut, bucket, key, nil, body, size, sha)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return apiError("put "+key, resp)
	}
	return nil
}

// Get returns an object's body and size; the caller closes it.
func (c *Client) Get(ctx context.Context, bucket, key string) (io.ReadCloser, int64, error) {
	resp, err := c.do(ctx, http.MethodGet, bucket, key, nil, nil, 0, "")
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		return nil, 0, apiError("get "+key, resp)
	}
	return resp.Body, resp.ContentLength, nil
}

// Delete removes an object; one that's already gone is fine.
func (c *Client) Delete(ctx context.Context, bucket, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, bucket, key, nil, nil, 0, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return apiError("delete "+key, resp)
	}
	return nil
}

// List returns every object under prefix (ListObjectsV2, following
// continuation tokens).
func (c *Client) List(ctx context.Context, bucket, prefix string) ([]Object, error) {
	var out []Object
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"1000"}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := c.do(ctx, http.MethodGet, bucket, "", q, nil, 0, "")
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return nil, apiError("list "+prefix, resp)
		}
		var page struct {
			Contents []struct {
				Key  string `xml:"Key"`
				Size string `xml:"Size"`
			} `xml:"Contents"`
			IsTruncated bool   `xml:"IsTruncated"`
			NextToken   string `xml:"NextContinuationToken"`
		}
		if err := xml.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("s3: list %s: %w", prefix, err)
		}
		for _, o := range page.Contents {
			n, _ := strconv.ParseInt(o.Size, 10, 64)
			out = append(out, Object{Key: o.Key, Size: n})
		}
		if !page.IsTruncated || page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}
