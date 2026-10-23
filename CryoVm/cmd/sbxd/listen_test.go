package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The socket is owner-only by default; with -sock-group, exactly 0660 and
// owned by that group. Never open to everyone.
func TestSocketPermissions(t *testing.T) {
	dir := t.TempDir()
	ln, err := listen(filepath.Join(dir, "a.sock"), "")
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "a.sock"))
	ln.Close()
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("default: %v, want 0600", fi.Mode().Perm())
	}

	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("no name for gid %d: %v", os.Getgid(), err)
	}
	ln, err = listen(filepath.Join(dir, "b.sock"), g.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, _ = os.Stat(filepath.Join(dir, "b.sock"))
	if fi.Mode().Perm() != 0o660 || int(fi.Sys().(*syscall.Stat_t).Gid) != os.Getgid() {
		t.Fatalf("with -sock-group %s: %v gid %d, want 0660 gid %d", g.Name, fi.Mode().Perm(), fi.Sys().(*syscall.Stat_t).Gid, os.Getgid())
	}
	if _, err := listen(filepath.Join(dir, "c.sock"), "no-such-group-sbx"); err == nil {
		t.Fatal("an unknown group should be refused")
	}
}

// One sbxd per registry and state directory: a second lock on the same path
// is refused, naming the holder; once released, it can be taken again.
func TestLockExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reg.db.lock")
	release, err := lockExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockExclusive(path); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("another sbxd (pid %d)", os.Getpid())) {
		t.Fatalf("a second lock: %v", err)
	}
	release()
	again, err := lockExclusive(path)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	again()
}
