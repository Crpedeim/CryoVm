package guest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityFilesAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	ident := newIdentity("first", dir)
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(b))
	}
	id1, gen1 := ident.get()
	if read("sandbox-id") != "first" || read("generation") != gen1 || len(gen1) != 32 || id1 != "first" {
		t.Fatalf("files: id %q gen %q (want %q)", read("sandbox-id"), read("generation"), gen1)
	}
	env := ident.env([]string{"PATH=/bin", "SBX_SANDBOX_ID=stale", "SBX_GENERATION=stale", "SBX_IDENTITY_DIR=stale"})
	if strings.Join(env, " ") != "PATH=/bin SBX_SANDBOX_ID=first SBX_GENERATION="+gen1+" SBX_IDENTITY_DIR="+dir {
		t.Fatalf("env: stale values must be replaced, not duplicated: %v", env)
	}
	if prev := ident.set("second", ""); prev != "first" {
		t.Fatalf("set returned %q, want the previous ID", prev)
	}
	_, gen2 := ident.get()
	if read("sandbox-id") != "second" || gen2 == gen1 || read("generation") != gen2 {
		t.Fatalf("after set: id %q, generation %q (was %q)", read("sandbox-id"), gen2, gen1)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}
