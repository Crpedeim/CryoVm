package daemon

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Crpedeim/sbx/internal/client"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/mcp"
)

// mcpSession speaks MCP to a server over pipes, as Claude Code would over
// sbx-mcp's stdin and stdout.
type mcpSession struct {
	t    *testing.T
	in   io.Writer
	out  *bufio.Reader
	next int
}

func startMCP(t *testing.T, c *client.Client, id string, workDir string) *mcpSession {
	t.Helper()
	tools := mcp.NewSandbox(c, id)
	if workDir != "" {
		tools.WorkDir = workDir // the stand-in's "sandbox" is this machine
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = mcp.Serve(ctx, tools, inR, outW, "test")
		outW.Close()
		close(done)
	}()
	t.Cleanup(func() { inW.Close(); cancel(); <-done; tools.Close() })
	return &mcpSession{t: t, in: inW, out: bufio.NewReaderSize(outR, 1<<20)}
}

type rpcReply struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (s *mcpSession) raw(line string) rpcReply {
	s.t.Helper()
	fmt.Fprintln(s.in, line)
	got, err := s.out.ReadString('\n')
	if err != nil {
		s.t.Fatalf("reading the reply: %v", err)
	}
	var r rpcReply
	if err := json.Unmarshal([]byte(got), &r); err != nil {
		s.t.Fatalf("a reply that isn't JSON: %q", got)
	}
	return r
}

func (s *mcpSession) call(method string, params any) rpcReply {
	s.t.Helper()
	s.next++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": s.next, "method": method, "params": params})
	return s.raw(string(b))
}

// tool calls a tool and returns its text, and whether it was an error.
func (s *mcpSession) tool(name string, args map[string]any) (string, bool, []mcp.Content) {
	s.t.Helper()
	r := s.call("tools/call", map[string]any{"name": name, "arguments": args})
	if r.Error != nil {
		s.t.Fatalf("%s: protocol error %d: %s", name, r.Error.Code, r.Error.Message)
	}
	var res mcp.Result
	_ = json.Unmarshal(r.Result, &res)
	var texts []string
	for _, c := range res.Content {
		if c.Type == "text" {
			texts = append(texts, c.Text)
		}
	}
	return strings.Join(texts, "\n"), res.IsError, res.Content
}

func TestMCPProtocol(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "proto"})
	s := startMCP(t, e.c, sb.ID, t.TempDir())
	var init struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		Instructions    string         `json:"instructions"`
	}
	_ = json.Unmarshal(s.call("initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}}).Result, &init)
	if init.ProtocolVersion != "2025-03-26" || init.Capabilities["tools"] == nil || !strings.Contains(init.Instructions, "proto") {
		t.Fatalf("initialize: %+v", init)
	}
	_ = json.Unmarshal(s.call("initialize", map[string]any{"protocolVersion": "1999-01-01"}).Result, &init)
	if init.ProtocolVersion != "2025-06-18" {
		t.Fatalf("an unknown version should get our newest: %q", init.ProtocolVersion)
	}
	fmt.Fprintln(s.in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`) // no reply expected
	if r := s.call("ping", nil); r.Error != nil || string(r.Result) != "{}" {
		t.Fatalf("ping: %+v", r)
	}
	var list struct {
		Tools []mcp.Tool `json:"tools"`
	}
	_ = json.Unmarshal(s.call("tools/list", nil).Result, &list)
	var names []string
	for _, tl := range list.Tools {
		names = append(names, tl.Name)
		// The binding is structural: no tool can be pointed at another sandbox.
		for prop := range tl.InputSchema["properties"].(map[string]any) {
			if strings.Contains(prop, "sandbox") {
				t.Errorf("tool %s takes %q: a session must not reach other sandboxes", tl.Name, prop)
			}
		}
		if tl.Description == "" {
			t.Errorf("tool %s has no description", tl.Name)
		}
	}
	if got := strings.Join(names, " "); got != "shell read_file write_file list_files start_process process_logs fork browse sandbox_info" {
		t.Fatalf("tools: %s", got)
	}
	if r := s.call("resources/list", nil); r.Error == nil || r.Error.Code != -32601 {
		t.Fatalf("an unknown method: %+v", r)
	}
	if r := s.call("tools/call", map[string]any{"name": "rm_rf"}); r.Error == nil || r.Error.Code != -32602 {
		t.Fatalf("an unknown tool: %+v", r)
	}
	if r := s.raw("this is not json"); r.Error == nil || r.Error.Code != -32700 {
		t.Fatalf("garbage: %+v", r)
	}
}

// The plan's done-when, part one: commands with state carried between calls.
func TestMCPShellCarriesState(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "sh"})
	s := startMCP(t, e.c, sb.ID, t.TempDir())
	dir := t.TempDir()
	expect := func(cmd, want string) {
		t.Helper()
		got, isErr, _ := s.tool("shell", map[string]any{"command": cmd})
		if got != want || isErr {
			t.Fatalf("shell %q:\n got %q\nwant %q", cmd, got, want)
		}
	}
	expect("cd "+dir+" && export X=42 && echo ok", "ok\n[exit code 0]")
	expect("pwd; echo $X", dir+"\n42\n[exit code 0]")
	expect("false", "[exit code 1]")
	expect("(exit 7)", "[exit code 7]")
	expect("printf no-newline", "no-newline\n[exit code 0]")
	expect("for i in 1 2 3; do\n  echo line $i\ndone", "line 1\nline 2\nline 3\n[exit code 0]")
	expect(`echo "it's \"quoted\""`, "it's \"quoted\"\n[exit code 0]")
	expect("echo out; echo err >&2", "out\nerr\n[exit code 0]")

	// Long output: its beginning and end, and a file for the rest.
	long, isErr, _ := s.tool("shell", map[string]any{"command": "seq 1 30000"})
	if isErr || !strings.HasPrefix(long, "1\n2\n3\n") || !strings.HasSuffix(long, "29999\n30000\n[exit code 0]") || !strings.Contains(long, "omitted here") {
		t.Fatalf("long output: %d bytes, starts %q, ends %q", len(long), long[:20], long[len(long)-40:])
	}
	file := long[strings.Index(long, "full text is in ")+len("full text is in "):]
	file = file[:strings.Index(file, ":")]
	page, _, _ := s.tool("read_file", map[string]any{"path": file, "offset": 100000, "limit": 50})
	if !strings.HasPrefix(page, "\n19657") && !strings.Contains(page, "next offset 100050") {
		t.Fatalf("paging through the saved output: %q", page)
	}

	// A timeout interrupts the command; the session, and its state, live on.
	start := time.Now()
	got, isErr, _ := s.tool("shell", map[string]any{"command": "echo before; sleep 30", "timeout_s": 1})
	if !isErr || !strings.Contains(got, "before") || !strings.Contains(got, "timed out after 1s and interrupted") || time.Since(start) > 10*time.Second {
		t.Fatalf("timeout: %q after %s", got, time.Since(start))
	}
	expect("echo $X; pwd", "42\n"+dir+"\n[exit code 0]")
}

// The plan's done-when, part two: paging through a long log.
func TestMCPFilesAndLogs(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "files"})
	s := startMCP(t, e.c, sb.ID, t.TempDir())
	dir := t.TempDir()

	if got, isErr, _ := s.tool("write_file", map[string]any{"path": dir + "/deep/er/notes.txt", "content": "0123456789abcdef"}); isErr {
		t.Fatalf("write_file: %s", got)
	}
	if got, _, _ := s.tool("list_files", map[string]any{"path": dir + "/deep/er"}); !strings.Contains(got, "16  notes.txt") {
		t.Fatalf("list_files: %q", got)
	}
	if got, _, _ := s.tool("read_file", map[string]any{"path": dir + "/deep/er/notes.txt", "offset": 4, "limit": 6}); got != "456789\n[bytes 4-10 of 16; next offset 10]" {
		t.Fatalf("read_file page: %q", got)
	}
	if got, _, _ := s.tool("read_file", map[string]any{"path": dir + "/deep/er/notes.txt", "offset": 10}); got != "abcdef\n[bytes 10-16 of 16: the end of the file]" {
		t.Fatalf("read_file to the end: %q", got)
	}
	if got, isErr, _ := s.tool("read_file", map[string]any{"path": dir}); !isErr || !strings.Contains(got, "is a directory") {
		t.Fatalf("read_file of a directory: %q", got)
	}

	started, _, _ := s.tool("start_process", map[string]any{"command": "seq 1 40000", "cwd": dir})
	proc := strings.Fields(started)[2]
	deadline := time.Now().Add(10 * time.Second)
	var all strings.Builder
	offset, pages := 0, 0
	for {
		got, isErr, _ := s.tool("process_logs", map[string]any{"process_id": proc, "offset": offset, "limit": 50000})
		if isErr {
			t.Fatalf("process_logs: %s", got)
		}
		cut := strings.LastIndex(got, "\n[")
		all.WriteString(got[:cut])
		footer := got[cut:]
		pages++
		// Always continue from the stated offset, as an agent polling a
		// running process would.
		if !strings.Contains(footer, "next offset") {
			t.Fatalf("every page must state the next offset: %q", footer)
		}
		fmt.Sscanf(footer[strings.Index(footer, "next offset")+len("next offset "):], "%d", &offset)
		if strings.Contains(footer, "more follows") {
			continue
		}
		if strings.Contains(footer, "exited with code 0") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the process never finished: %q", footer)
		}
		time.Sleep(50 * time.Millisecond)
	}
	want, _ := exec.Command("seq", "1", "40000").Output()
	if all.String() != string(want) || pages < 4 {
		t.Fatalf("the pages, joined: %d bytes in %d pages; want %d bytes in several", all.Len(), pages, len(want))
	}
}

func TestMCPForkAndInfo(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "src"})
	s := startMCP(t, e.c, sb.ID, t.TempDir())
	got, isErr, _ := s.tool("fork", map[string]any{"count": 2})
	if isErr || !strings.Contains(got, "into 2 new sandbox(es)") || !strings.Contains(got, "This session stays in src") {
		t.Fatalf("fork: %q", got)
	}
	if got, _, _ := s.tool("sandbox_info", map[string]any{}); !strings.Contains(got, "sandbox src: running") || !strings.Contains(got, "network: none") {
		t.Fatalf("sandbox_info: %q", got)
	}
}

// A sandbox without a browser gets a clear answer. It runs on every machine:
// a stand-in "playwright" package that refuses to import is put first on the
// import path, so Playwright is missing whether or not this machine has it.
// (It used to skip where Playwright was installed, and the no-browser path
// went untested, and broken, until a machine without Playwright ran it.)
func TestMCPBrowseWithoutABrowser(t *testing.T) {
	shadow := t.TempDir()
	_ = os.MkdirAll(filepath.Join(shadow, "playwright"), 0o755)
	_ = os.WriteFile(filepath.Join(shadow, "playwright", "__init__.py"), []byte("raise ImportError('not installed here')\n"), 0o644)
	t.Setenv("PYTHONPATH", shadow) // inherited by the stand-in agent's children
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "plain"})
	s := startMCP(t, e.c, sb.ID, t.TempDir())
	got, isErr, _ := s.tool("browse", map[string]any{"url": "https://example.com"})
	if !isErr || !strings.Contains(got, "sbx create -image browser") {
		t.Fatalf("browse without a browser: %q", got)
	}
	if got, isErr, _ := s.tool("browse", map[string]any{"url": "file:///etc/passwd"}); !isErr || !strings.Contains(got, "http:// or https://") {
		t.Fatalf("browse of a file URL: %q", got)
	}
}

// browse for real, where this machine has Playwright and Chromium (the
// stand-in's "sandbox" is this machine): a local page's text comes back,
// and its screenshot comes back as an image a model can look at.
func TestMCPBrowseForReal(t *testing.T) {
	probe := "from playwright.sync_api import sync_playwright\nwith sync_playwright() as p:\n    p.chromium.launch().close()"
	if exec.Command("python3", "-c", probe).Run() != nil {
		t.Skip("no Playwright with a working Chromium on this machine")
	}
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>sbx docs</title></head><body><h1>Install</h1><p>Run pip install sbx.</p></body></html>`)
	}))
	defer page.Close()
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "web"})
	s := startMCP(t, e.c, sb.ID, t.TempDir())
	got, isErr, content := s.tool("browse", map[string]any{"url": page.URL, "screenshot": true})
	if isErr || !strings.HasPrefix(got, "sbx docs\nURL: "+page.URL) || !strings.Contains(got, "(HTTP 200)") || !strings.Contains(got, "Install") || !strings.Contains(got, "Run pip install sbx.") {
		t.Fatalf("browse: %q", got)
	}
	var img *mcp.Content
	for i := range content {
		if content[i].Type == "image" {
			img = &content[i]
		}
	}
	if img == nil || img.MimeType != "image/png" {
		t.Fatalf("the screenshot should come back as an image: %+v", content)
	}
	png, err := base64.StdEncoding.DecodeString(img.Data)
	if err != nil || !strings.HasPrefix(string(png), "\x89PNG") || len(png) < 2000 {
		t.Fatalf("not a real PNG: %d bytes, %v", len(png), err)
	}
	t.Logf("browse: %d bytes of text, a %d KiB screenshot", len(got), len(png)/1024)
}

// Day 22: with sbx-mcp connected, the sandbox still idle-pauses (the shell
// is detached between commands; an attached one counts as activity), and
// the next command wakes it. (The stand-in doesn't carry shell sessions
// through a restore; the integration test checks state survives on gVisor.)
func TestMCPSandboxSleepsBetweenCommands(t *testing.T) {
	e := start(t)
	sb := napper(t, e, "mcpnap")
	s := startMCP(t, e.c, sb.ID, t.TempDir())
	if got, _, _ := s.tool("shell", map[string]any{"command": "echo working"}); got != "working\n[exit code 0]" {
		t.Fatalf("first command: %q", got)
	}
	waitState(t, e, sb.ID, api.Paused, 5*time.Second) // never happens if the shell stays attached
	got, isErr, _ := s.tool("shell", map[string]any{"command": "echo awake"})
	if isErr || !strings.HasSuffix(got, "awake\n[exit code 0]") {
		t.Fatalf("after the sandbox slept: %q", got)
	}
	if rec, _ := e.c.Get(tctx(t), sb.ID); rec.State != api.Running {
		t.Fatalf("the command should have woken it: %s", rec.State)
	}
}

// Day 22: failures come with what happened, the likely why, and what to do.
func TestMCPExplainsFailures(t *testing.T) {
	n := newFakeNet()
	e := start(t, withNet(n))
	ctx := tctx(t)
	plain, _ := e.c.Create(ctx, api.CreateRequest{ID: "plain"})
	s := startMCP(t, e.c, plain.ID, t.TempDir())
	expect := func(s *mcpSession, cmd string, timeout int, wants ...string) {
		t.Helper()
		got, _, _ := s.tool("shell", map[string]any{"command": cmd, "timeout_s": timeout})
		for _, w := range wants {
			if !strings.Contains(got, w) {
				t.Fatalf("shell %q:\n%s\nwant it to say %q", cmd, got, w)
			}
		}
	}
	expect(s, "no-such-command-sbx", 30, "[exit code 127: command not found")
	expect(s, "sh -c 'kill -9 $$'", 30, "[exit code 137: killed (SIGKILL): most often for running out of memory]")
	_ = e.reg.Note(ctx, plain.ID, "memory guard: killed tail (pid 9, 218 MiB) at 230 of 256 MiB")
	expect(s, "sh -c 'kill -9 $$'", 30, "killed (SIGKILL) by the sandbox's memory guard: killed tail (pid 9, 218 MiB) at 230 of 256 MiB")
	expect(s, "echo 'curl: (6) Could not resolve host: example.com'; false", 30, "[exit code 1: this sandbox has no network at all]")
	expect(s, "cat", 1, "If it was waiting for input, it can't get any")
	expect(s, "echo recovered", 30, "recovered\n[exit code 0]")
	// `exit` in a persistent shell ends the shell: say so, and what it costs.
	expect(s, "cd /tmp && export KEEP=1", 30, "[exit code 0]")
	expect(s, "echo bye; exit 3", 30, "bye", "the shell itself exited", "use a subshell: (exit 1)")
	expect(s, "echo \"KEEP=$KEEP\"; pwd", 30, "a new one started", "KEEP=\n")

	allow, _ := e.c.Create(ctx, api.CreateRequest{ID: "allow", Network: true})
	sa := startMCP(t, e.c, allow.ID, t.TempDir())
	expect(sa, "echo 'socket.gaierror: [Errno -3] Temporary failure in name resolution'; (exit 1)", 30, "no DNS and no direct route out", "HTTPS_PROXY")
	expect(sa, "echo 'Tunnel connection failed: 403 Forbidden'; (exit 1)", 30, "only the names on the proxy's allowlist")
	browse, _ := e.c.Create(ctx, api.CreateRequest{ID: "web", Network: true, Policy: "browse"})
	sw := startMCP(t, e.c, browse.ID, t.TempDir())
	expect(sw, "echo 'net::ERR_TUNNEL_CONNECTION_FAILED'; (exit 1)", 30, "never private addresses or the cloud metadata service")

	if got, isErr, _ := s.tool("read_file", map[string]any{"path": "/no/such/file"}); !isErr || !strings.Contains(got, "not found. Paths are absolute or relative to /root") {
		t.Fatalf("a missing file: %q", got)
	}
	dir := t.TempDir()
	started, _, _ := s.tool("start_process", map[string]any{"command": "true", "cwd": dir})
	real := strings.Fields(started)[2]
	if got, isErr, _ := s.tool("process_logs", map[string]any{"process_id": "p-nope"}); !isErr || !strings.Contains(got, "This sandbox's processes are: "+real) {
		t.Fatalf("an unknown process: %q", got)
	}

	if _, err := e.c.Destroy(ctx, plain.ID); err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct {
		tool string
		args map[string]any
	}{{"shell", map[string]any{"command": "echo hi"}}, {"read_file", map[string]any{"path": "/etc/hostname"}}} {
		if got, isErr, _ := s.tool(call.tool, call.args); !isErr || !strings.Contains(got, "this session's sandbox, plain, is stopped") || !strings.Contains(got, "Start a new session") {
			t.Fatalf("%s on a destroyed sandbox: %q", call.tool, got)
		}
	}
}

// The descriptions say what a model must know before it trips over it.
func TestMCPDescriptionsWarnAboutTheSurprises(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "d"})
	tools := mcp.NewSandbox(e.c, sb.ID).Tools()
	desc := map[string]string{}
	for _, tl := range tools {
		desc[tl.Name] = tl.Description
	}
	for tool, must := range map[string][]string{
		"shell":         {"persistent", "no keyboard input", "start_process", "full text is saved"},
		"read_file":     {"next offset", "images"},
		"process_logs":  {"next offset", "still running"},
		"fork":          {"own session"},
		"browse":        {"-image browser", "metadata", "Playwright script"},
		"start_process": {"process_logs"},
	} {
		for _, m := range must {
			if !strings.Contains(desc[tool], m) {
				t.Errorf("%s's description should mention %q", tool, m)
			}
		}
	}
}

// Polling a process that's still writing: no byte is read twice or missed.
// (Before every page stated the next offset, a slow process's pages were
// read twice: a run as an unprivileged user, slower, caught it.)
func TestMCPPollingARunningProcess(t *testing.T) {
	e := start(t)
	sb, _ := e.c.Create(tctx(t), api.CreateRequest{ID: "poll"})
	s := startMCP(t, e.c, sb.ID, t.TempDir())
	started, _, _ := s.tool("start_process", map[string]any{"command": "for i in $(seq 1 40); do echo line $i; sleep 0.02; done", "cwd": t.TempDir()})
	proc := strings.Fields(started)[2]
	var all strings.Builder
	offset, polls := 0, 0
	for deadline := time.Now().Add(10 * time.Second); ; {
		got, _, _ := s.tool("process_logs", map[string]any{"process_id": proc, "offset": offset})
		cut := strings.LastIndex(got, "\n[")
		all.WriteString(got[:cut])
		footer := got[cut:]
		if !strings.Contains(footer, "next offset") {
			t.Fatalf("poll %d: the page doesn't say where to continue from: %q", polls+1, footer)
		}
		fmt.Sscanf(footer[strings.Index(footer, "next offset")+len("next offset "):], "%d", &offset)
		polls++
		if strings.Contains(footer, "exited") || time.Now().After(deadline) {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	var want strings.Builder
	for i := 1; i <= 40; i++ {
		fmt.Fprintf(&want, "line %d\n", i)
	}
	if all.String() != want.String() || polls < 3 {
		t.Fatalf("polled %d times; got %d bytes, want %d", polls, all.Len(), want.Len())
	}
}
