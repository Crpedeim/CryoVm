package fc

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type recorded struct {
	method, path string
	body         map[string]any
}

// fakeFirecracker serves HTTP on a Unix socket and records every request,
// so the client can be tested without KVM.
func fakeFirecracker(t *testing.T, status int, reply string) (string, func() []recorded) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "fc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var reqs []recorded
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		reqs = append(reqs, recorded{r.Method, r.URL.Path, body})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock, func() []recorded {
		mu.Lock()
		defer mu.Unlock()
		return append([]recorded(nil), reqs...)
	}
}

func TestBootSequence(t *testing.T) {
	sock, got := fakeFirecracker(t, http.StatusNoContent, "")
	c := NewClient(sock)
	ctx := context.Background()

	steps := []error{
		c.SetMachineConfig(ctx, MachineConfig{VcpuCount: 1, MemSizeMib: 256}),
		c.SetBootSource(ctx, BootSource{KernelImagePath: "/k", BootArgs: "console=ttyS0"}),
		c.SetDrive(ctx, Drive{DriveID: "rootfs", PathOnHost: "/r.ext4", IsRootDevice: true}),
		c.Start(ctx),
	}
	for i, err := range steps {
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}

	want := []struct {
		path, key string
		val       any
	}{
		{"/machine-config", "mem_size_mib", float64(256)},
		{"/boot-source", "kernel_image_path", "/k"},
		{"/drives/rootfs", "is_root_device", true},
		{"/actions", "action_type", "InstanceStart"},
	}
	reqs := got()
	if len(reqs) != len(want) {
		t.Fatalf("got %d requests, want %d", len(reqs), len(want))
	}
	for i, w := range want {
		r := reqs[i]
		if r.method != http.MethodPut || r.path != w.path {
			t.Errorf("request %d: got %s %s, want PUT %s", i, r.method, r.path, w.path)
		}
		if r.body[w.key] != w.val {
			t.Errorf("request %d: %s = %v, want %v", i, w.key, r.body[w.key], w.val)
		}
	}
}

func TestErrorIncludesFirecrackerMessage(t *testing.T) {
	sock, _ := fakeFirecracker(t, http.StatusBadRequest, `{"fault_message":"Invalid kernel path"}`)
	err := NewClient(sock).SetBootSource(context.Background(), BootSource{KernelImagePath: "/nope"})
	if err == nil || !strings.Contains(err.Error(), "Invalid kernel path") {
		t.Fatalf("want error carrying the fault message, got %v", err)
	}
}
