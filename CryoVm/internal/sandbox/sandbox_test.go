package sandbox

import "testing"

func TestValidateID(t *testing.T) {
	for _, ok := range []string{"a", "demo-1", "sbx-20261013"} {
		if err := ValidateID(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-x", "UPPER", "a/b", "../etc", "a b", "x;rm"} {
		if err := ValidateID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
