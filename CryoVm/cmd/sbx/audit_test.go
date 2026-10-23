package main

import "testing"

func TestAuditMarkFlagsOnlyProblems(t *testing.T) {
	for outcome, want := range map[string]string{"ok": " ", "allowed": " ", "error": "!", "denied": "!"} {
		if got := auditMark(outcome); got != want {
			t.Errorf("%s: %q, want %q", outcome, got, want)
		}
	}
}
