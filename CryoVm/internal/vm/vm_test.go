package vm

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHelperFirecracker is not a real test. When SBX_FAKE_FC is set, the test
// binary re-runs itself as a fake Firecracker that serves the API on
// --api-sock, so the lifecycle can be tested without KVM. Modes:
//
//	obedient: exits shortly after SendCtrlAltDel, like a guest that reboots
//	stubborn: ignores SendCtrlAltDel, like a hung guest
//	crash:    exits before opening the socket
func TestHelperFirecracker(t *testing.T) {
	mode := os.Getenv("SBX_FAKE_FC")
	if mode == "" {
		return
	}
	if mode == "crash" {
		os.Exit(1)
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	var sock string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--api-sock" {
			sock = args[i+1]
		}
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		os.Exit(3)
	}
	_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a struct {
			ActionType string `json:"action_type"`
		}
		_ = json.NewDecoder(r.Body).Decode(&a)
		w.WriteHeader(http.StatusNoContent)
		if a.ActionType == "SendCtrlAltDel" && mode == "obedient" {
			go func() { time.Sleep(50 * time.Millisecond); os.Exit(0) }()
		}
	}))
}

func fakeConfig(t *testing.T, mode string) Config {
	t.Helper()
	t.Setenv("SBX_FAKE_FC", mode)
	return Config{
		FirecrackerBin: os.Args[0],
		BinArgs:        []string{"-test.run=TestHelperFirecracker", "--"},
		SocketPath:     filepath.Join(t.TempDir(), "fc.sock"),
		KernelPath:     "/fake/vmlinux",
		RootfsPath:     "/fake/rootfs.ext4",
		VCPUs:          1,
		MemMiB:         128,
	}
}

func TestStartAndCleanShutdown(t *testing.T) {
	cfg := fakeConfig(t, "obedient")
	v, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := v.Shutdown(context.Background(), 2*time.Second); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if _, err := os.Stat(cfg.SocketPath); !os.IsNotExist(err) {
		t.Errorf("socket left behind after shutdown")
	}
}

func TestShutdownKillsStubbornGuest(t *testing.T) {
	v, err := Start(context.Background(), fakeConfig(t, "stubborn"))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	err = v.Shutdown(context.Background(), 200*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not shut down") {
		t.Fatalf("want a did-not-shut-down error, got %v", err)
	}
	select {
	case <-v.Exited():
	case <-time.After(time.Second):
		t.Fatal("process still running after kill")
	}
}

func TestStartFailsIfFirecrackerDies(t *testing.T) {
	_, err := Start(context.Background(), fakeConfig(t, "crash"))
	if err == nil || !strings.Contains(err.Error(), "exited before") {
		t.Fatalf("want an exited-before-ready error, got %v", err)
	}
}
