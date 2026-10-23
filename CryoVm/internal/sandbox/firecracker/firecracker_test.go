package firecracker

import (
	"context"
	"errors"
	"testing"

	"github.com/Crpedeim/sbx/internal/sandbox"
)

func TestExecIsUnsupportedUntilGuestAgent(t *testing.T) {
	_, err := (&Sandbox{id: "x"}).Exec(context.Background(), sandbox.ExecRequest{Args: []string{"true"}})
	if !errors.Is(err, sandbox.ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}

func TestCreateRequiresKernel(t *testing.T) {
	b, err := New(Config{SocketDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(context.Background(), sandbox.Spec{ID: "x", Rootfs: "/r.ext4"}); err == nil {
		t.Fatal("created a Firecracker sandbox without a kernel")
	}
}

func TestFilesAreUnsupportedUntilVsockAgent(t *testing.T) {
	_, err := (&Sandbox{id: "x"}).ReadFile(context.Background(), "/etc/hostname", nil)
	if !errors.Is(err, sandbox.ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}
