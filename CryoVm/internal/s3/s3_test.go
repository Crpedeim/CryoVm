package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// AWS's published SigV4 example for S3 ("GET Object", in the S3 API
// reference's signature-calculation examples): known keys, a fixed time,
// and the signature AWS prints. Reproducing it exactly means the
// canonical request, string to sign and key derivation are all right.
func TestSignatureMatchesAWSExample(t *testing.T) {
	c := &Client{
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Now:       func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) },
	}
	req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	c.Sign(req, emptyHash)
	got := req.Header.Get("Authorization")
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got != want {
		t.Fatalf("Authorization:\n got %s\nwant %s", got, want)
	}
}

// Against a real S3-compatible server that checks signatures (SeaweedFS or
// MinIO): set SBX_S3_ENDPOINT, SBX_S3_ACCESS_KEY, SBX_S3_SECRET_KEY.
func realClient(t *testing.T) *Client {
	t.Helper()
	ep := os.Getenv("SBX_S3_ENDPOINT")
	if ep == "" {
		t.Skip("no S3 server: set SBX_S3_ENDPOINT, SBX_S3_ACCESS_KEY, SBX_S3_SECRET_KEY")
	}
	return &Client{Endpoint: ep, AccessKey: os.Getenv("SBX_S3_ACCESS_KEY"), SecretKey: os.Getenv("SBX_S3_SECRET_KEY")}
}

func hashOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestAgainstARealServer(t *testing.T) {
	c := realClient(t)
	ctx := context.Background()
	bucket := os.Getenv("SBX_S3_BUCKET") // one bucket: a bucket per run exhausts a small server
	if bucket == "" {
		bucket = "sbx-test"
	}
	pre := fmt.Sprintf("test-%d/", time.Now().UnixNano())
	if err := c.MakeBucket(ctx, bucket); err != nil {
		t.Fatalf("make bucket: %v", err)
	}
	if err := c.MakeBucket(ctx, bucket); err != nil {
		t.Fatalf("making it again should be fine: %v", err)
	}
	body := bytes.Repeat([]byte("sandbox "), 300000)      // 2.4 MB
	key := pre + "checkpoints/ck-1/files/pages img+x.bin" // spaces and symbols in a key
	if err := c.Put(ctx, bucket, key, bytes.NewReader(body), int64(len(body)), hashOf(body)); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Does the server check a body against its signed hash? AWS S3 does;
	// SeaweedFS 4.48 doesn't (found here). So sbx can't rely on it: the
	// store verifies every download against the manifest's SHA-256 itself.
	if err := c.Put(ctx, bucket, pre+"checkpoints/ck-1/files/bad", strings.NewReader("tampered"), 8, hashOf([]byte("original"))); err == nil {
		t.Log("OBSERVED: this server accepted a body that doesn't match its signed SHA-256; downloads must be verified by the client")
		_ = c.Delete(ctx, bucket, pre+"checkpoints/ck-1/files/bad")
	} else {
		t.Logf("OBSERVED: this server refused a body that doesn't match its signed SHA-256: %v", err)
	}
	rc, size, err := c.Get(ctx, bucket, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if size != int64(len(body)) || !bytes.Equal(got, body) {
		t.Fatalf("get: %d bytes (size %d), want %d", len(got), size, len(body))
	}
	for i := 0; i < 3; i++ {
		_ = c.Put(ctx, bucket, fmt.Sprintf("%scheckpoints/ck-2/files/f%d", pre, i), strings.NewReader("x"), 1, hashOf([]byte("x")))
	}
	objs, err := c.List(ctx, bucket, pre+"checkpoints/")
	if err != nil || len(objs) != 4 {
		t.Fatalf("list: %v %v", objs, err)
	}
	if _, _, err := c.Get(ctx, bucket, pre+"checkpoints/nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a missing key: %v", err)
	}
	for _, o := range objs {
		if err := c.Delete(ctx, bucket, o.Key); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Delete(ctx, bucket, key); err != nil {
		t.Fatalf("deleting a deleted key should be fine: %v", err)
	}
	if objs, _ := c.List(ctx, bucket, pre+"checkpoints/"); len(objs) != 0 {
		t.Fatalf("after deleting: %v", objs)
	}
	bad := *c
	bad.SecretKey = "wrong"
	if err := bad.Put(ctx, bucket, pre+"x", strings.NewReader("x"), 1, hashOf([]byte("x"))); err == nil {
		t.Fatal("a wrong secret should be refused")
	}
}
