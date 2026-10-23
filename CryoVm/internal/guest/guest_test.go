package guest

import (
	"os"
	"reflect"
	"syscall"
	"testing"
)

func TestMergeEnvOverridesInsteadOfDuplicating(t *testing.T) {
	got := mergeEnv([]string{"PATH=/bin", "HOME=/root", "FOO=old"}, []string{"FOO=new", "BAR=1"})
	want := []string{"PATH=/bin", "HOME=/root", "FOO=new", "BAR=1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := mergeEnv([]string{"A=1"}, nil); !reflect.DeepEqual(got, []string{"A=1"}) {
		t.Fatalf("no extras: %v", got)
	}
}

func TestErrCodeMapping(t *testing.T) {
	cases := map[error]string{
		syscall.EROFS:   "read_only",
		syscall.ENOENT:  "not_found",
		syscall.EACCES:  "permission",
		syscall.EPERM:   "permission",
		syscall.EISDIR:  "is_dir",
		syscall.ENOTDIR: "not_dir",
		syscall.EEXIST:  "exists",
		syscall.EIO:     "io",
	}
	for err, want := range cases {
		wrapped := &os.PathError{Op: "open", Path: "/x", Err: err}
		if got := errCode(wrapped); got != want {
			t.Errorf("%v: got %s, want %s", err, got, want)
		}
	}
}
