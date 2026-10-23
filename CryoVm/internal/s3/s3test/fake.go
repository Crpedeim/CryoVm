// Package s3test is an in-memory S3 server for tests: put, get, delete,
// list (v2) and make-bucket, on path-style URLs. It doesn't check
// signatures (the s3 package's own tests do that against AWS's example and
// a real server); it can corrupt objects and fail requests on demand.
package s3test

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
)

type Server struct {
	*httptest.Server
	mu        sync.Mutex
	objects   map[string][]byte // "bucket/key"
	failing   bool              // every request fails (a store that went away)
	putsLeft  int               // with failAfter: uploads still allowed
	failAfter bool
}

func New() *Server {
	s := &Server{objects: map[string][]byte{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Objects returns a copy of what's stored, by "bucket/key".
func (s *Server) Objects() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range s.objects {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// Set replaces (or adds) an object's bytes, to corrupt or forge one.
func (s *Server) Set(bucketKey string, b []byte) {
	s.mu.Lock()
	s.objects[bucketKey] = b
	s.mu.Unlock()
}

// FailAfterPuts lets n more objects be stored, then fails every request:
// a store connection dropping partway through an upload.
func (s *Server) FailAfterPuts(n int) {
	s.mu.Lock()
	s.putsLeft, s.failAfter = n, true
	s.mu.Unlock()
}

// Fail makes every request fail (true) or work again (false).
func (s *Server) Fail(on bool) {
	s.mu.Lock()
	s.failing, s.failAfter = on, false
	s.mu.Unlock()
}

func xmlError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.failAfter && r.Method == http.MethodPut && r.URL.Path != "" {
		if s.putsLeft == 0 {
			s.failing = true
		}
		s.putsLeft--
	}
	failing := s.failing
	s.mu.Unlock()
	if failing {
		xmlError(w, http.StatusServiceUnavailable, "ServiceUnavailable")
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	full := bucket + "/" + key
	switch {
	case r.Method == http.MethodPut && key == "":
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPut:
		b, err := io.ReadAll(r.Body)
		if err != nil {
			xmlError(w, http.StatusBadRequest, "IncompleteBody")
			return
		}
		s.mu.Lock()
		s.objects[full] = b
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && key == "":
		prefix := bucket + "/" + r.URL.Query().Get("prefix")
		s.mu.Lock()
		var keys []string
		for k := range s.objects {
			if strings.HasPrefix(k, prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		type entry struct {
			Key  string `xml:"Key"`
			Size int    `xml:"Size"`
		}
		var res struct {
			XMLName     xml.Name `xml:"ListBucketResult"`
			Contents    []entry  `xml:"Contents"`
			IsTruncated bool     `xml:"IsTruncated"`
		}
		for _, k := range keys {
			res.Contents = append(res.Contents, entry{Key: strings.TrimPrefix(k, bucket+"/"), Size: len(s.objects[k])})
		}
		s.mu.Unlock()
		_ = xml.NewEncoder(w).Encode(res)
	case r.Method == http.MethodGet:
		s.mu.Lock()
		b, ok := s.objects[full]
		s.mu.Unlock()
		if !ok {
			xmlError(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		_, _ = w.Write(b)
	case r.Method == http.MethodDelete:
		s.mu.Lock()
		delete(s.objects, full)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		xmlError(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}
