package guest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// fakeProc writes /proc/<pid>/status files: pid → (ppid, name, rss in kB).
func fakeProc(t *testing.T, procs map[int][3]any) string {
	t.Helper()
	root := t.TempDir()
	for pid, p := range procs {
		dir := filepath.Join(root, fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		status := fmt.Sprintf("Name:\t%s\nState:\tS (sleeping)\nPPid:\t%d\nVmRSS:\t%d kB\n", p[1], p[0], p[2])
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestLargestDescendantIgnoresStrangers(t *testing.T) {
	// The agent is 100. 900 is a huge process that isn't ours (in a test,
	// that could be anything on the machine): it must never be chosen.
	root := fakeProc(t, map[int][3]any{
		1:   {0, "init", 1000},
		100: {1, "sbx-agent", 50000}, // the agent itself: never a candidate
		200: {100, "sh", 2000},
		201: {200, "tail", 240000}, // a grandchild: the real hog
		202: {100, "sleep", 500},
		900: {1, "stranger", 9000000},
	})
	got, ok := largestDescendant(root, 100)
	if !ok || got.pid != 201 || got.command != "tail" || got.rss != 240000<<10 {
		t.Fatalf("picked %+v, want tail (201)", got)
	}
	// A root with no descendants: nothing to pick.
	if _, ok := largestDescendant(root, 202); ok {
		t.Fatal("picked something with no descendants")
	}
}
