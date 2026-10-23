package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Crpedeim/sbx/internal/client"
)

// Day 22: errors written for a model. A model reading a tool's result can't
// see the system, so each failure says what happened, the likely why, and
// what to do next.

// exitMeaning explains an exit code that means more than "it failed".
func (s *Sandbox) exitMeaning(ctx context.Context, code int) string {
	switch code {
	case 0, 1:
		return "" // success, or an ordinary failure the output explains
	case 2:
		return "often a usage error: wrong arguments or options"
	case 124:
		return "timeout(1) stopped it"
	case 126:
		return "the command exists but couldn't be run: not executable, or not a program"
	case 127:
		return "command not found: it isn't installed in this sandbox or isn't on PATH. Python packages can be installed with pip if the egress policy allows the index (see sandbox_info)"
	case 130:
		return "interrupted (Ctrl-C)"
	case 134:
		return "aborted (SIGABRT): the program crashed itself, often on a failed assertion"
	case 137:
		if guard := s.recentGuardKill(ctx); guard != "" {
			return "killed (SIGKILL) by the sandbox's memory guard: " + guard + ". Use less memory (smaller inputs, streaming), or ask for a sandbox with more"
		}
		return "killed (SIGKILL): most often for running out of memory"
	case 139:
		return "segmentation fault (SIGSEGV): the program crashed"
	case 143:
		return "terminated (SIGTERM)"
	}
	if code > 128 && code < 160 {
		return fmt.Sprintf("ended by signal %d", code-128)
	}
	return ""
}

// recentGuardKill finds the memory guard's note in the last minute, if any.
func (s *Sandbox) recentGuardKill(ctx context.Context) string {
	evs, err := s.c.Events(ctx, s.id)
	if err != nil {
		return ""
	}
	for i := len(evs) - 1; i >= 0 && i >= len(evs)-20; i-- {
		if strings.HasPrefix(evs[i].Detail, "memory guard: ") && time.Since(evs[i].At) < time.Minute {
			return strings.TrimPrefix(evs[i].Detail, "memory guard: ")
		}
	}
	return ""
}

// networkSigns are what network refusals look like in common tools' output.
var networkSigns = []struct{ sign, kind string }{
	{"Tunnel connection failed: 403", "refused"},
	{"ProxyError", "refused"},
	{"ERR_TUNNEL_CONNECTION_FAILED", "refused"},
	{"403 Forbidden", "refused"},
	{"Temporary failure in name resolution", "dns"},
	{"Could not resolve host", "dns"},
	{"Name or service not known", "dns"},
	{"getaddrinfo", "dns"},
	{"Network is unreachable", "direct"},
	{"Connection timed out", "direct"},
}

// networkHint explains a network failure it recognizes in a command's
// output, by this sandbox's actual network and policy.
func (s *Sandbox) networkHint(ctx context.Context, output string) string {
	kind := ""
	for _, n := range networkSigns {
		if strings.Contains(output, n.sign) {
			kind = n.kind
			break
		}
	}
	if kind == "" {
		return ""
	}
	sb, err := s.c.Get(ctx, s.id)
	if err != nil {
		return ""
	}
	switch {
	case sb.NetSlot == 0:
		return "this sandbox has no network at all"
	case kind == "refused" && sb.EgressPolicy == "browse":
		return "the egress proxy refused the destination: this sandbox may reach the public internet on ports 80 and 443, never private addresses or the cloud metadata service"
	case kind == "refused":
		return "the egress proxy refused the destination: this sandbox may reach only the names on the proxy's allowlist"
	default:
		return "this sandbox has no DNS and no direct route out: everything goes through the egress proxy, so use tools that honor HTTPS_PROXY (pip, curl, Python's urllib and requests do; a browser needs it passed explicitly)"
	}
}

// explainErr turns a client error into what a model can act on. subject
// names what the tool was working on; hint is what to do if it's missing.
func (s *Sandbox) explainErr(ctx context.Context, err error, subject, hint string) Result {
	if gone := s.gone(ctx); gone != "" {
		return errResult("%s", gone)
	}
	switch {
	case errors.Is(err, client.ErrNotFound):
		return errResult("%s: not found. %s", subject, hint)
	case errors.Is(err, client.ErrConflict):
		return errResult("%s: the sandbox is busy (a command is still running, or a connection is open). Wait for it to finish, then try again. (%v)", subject, err)
	case errors.Is(err, client.ErrForbidden):
		return errResult("%s: not allowed: %v", subject, err)
	}
	return errResult("%s: %v", subject, err)
}

// gone says so if this session's sandbox no longer exists.
func (s *Sandbox) gone(ctx context.Context) string {
	sb, err := s.c.Get(ctx, s.id)
	switch {
	case errors.Is(err, client.ErrNotFound):
		return fmt.Sprintf("this session's sandbox, %s, no longer exists. Its tools can't do anything more: start a new session.", s.id)
	case err == nil && sb.State.Terminal():
		return fmt.Sprintf("this session's sandbox, %s, is %s (it may have expired or been destroyed). Start a new session.", s.id, sb.State)
	}
	return ""
}
