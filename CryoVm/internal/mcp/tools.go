package mcp

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Crpedeim/sbx/internal/api"
	"github.com/Crpedeim/sbx/internal/client"
)

// Sandbox is the tool set for one sandbox. No tool takes a sandbox ID: the
// sandbox is fixed when the server starts, so no tool can reach another.
type Sandbox struct {
	c  *client.Client
	id string
	sh *shell

	// WorkDir is where long outputs and browse's helper go, inside the
	// sandbox (default /tmp/.sbx-mcp).
	WorkDir string

	mu       sync.Mutex
	saved    int                  // how many long outputs were saved to files
	helperUp bool                 // browse's helper is in the sandbox
	forwards map[int]net.Listener // forward_port's, by port inside: open until the session ends
}

func NewSandbox(c *client.Client, id string) *Sandbox {
	return &Sandbox{c: c, id: id, sh: &shell{c: c, sandbox: id}, WorkDir: "/tmp/.sbx-mcp", forwards: map[int]net.Listener{}}
}

func (s *Sandbox) Close() {
	s.sh.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ln := range s.forwards {
		ln.Close()
	}
}

const (
	maxText  = 20000 // bytes of text a result carries
	headText = 8000  // of which the beginning
)

func (s *Sandbox) Instructions() string {
	return fmt.Sprintf("These tools act inside one sandbox, %s: an isolated Linux machine (gVisor). "+
		"shell keeps its working directory and variables between calls. "+
		"Long outputs are cut to their beginning and end; the full text is saved in a file you can page through with read_file. "+
		"Network access, if any, goes through an egress proxy that may refuse destinations. "+
		"To show the user a web app or any other server you run in the sandbox, use forward_port: it gives them a URL to open on their machine.", s.id)
}

func schema(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func num(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }

func intIn(desc string, min, max int) map[string]any {
	return map[string]any{"type": "integer", "description": desc, "minimum": min, "maximum": max}
}

// Tools are described for a model (Day 22): when to use each, what comes
// back, and the limits that would otherwise surprise it.
func (s *Sandbox) Tools() []Tool {
	return []Tool{
		{"shell", "Run a command in the sandbox's persistent bash session and get its output (stdout and stderr " +
			"together) and exit code. The working directory, variables, and activated environments carry over to " +
			"later calls. Commands get no keyboard input: don't start interactive programs (a bare python3, editors, " +
			"prompts); use scripts, -y style flags, or files instead. A command that runs past timeout_s is " +
			"interrupted with Ctrl-C and its output so far returned. For servers, builds, or anything that takes " +
			"minutes, use start_process. Long output is cut to its beginning and end; the full text is saved to a " +
			"file named in the result, for read_file. Failures come with an explanation of the exit code, and of " +
			"network refusals.",
			schema(map[string]any{
				"command":   str("The command line, as you would type it. Several lines are fine."),
				"timeout_s": intIn("Seconds before it's interrupted (default 120).", 1, 1800),
			}, "command")},
		{"read_file", "Read a file in the sandbox, a page at a time: up to limit bytes from offset. Each page ends " +
			"with the byte range it covered and, if there's more, the next offset to ask for. Use it to page " +
			"through long outputs the other tools saved. Images (png, jpg, gif, webp) come back as images you can " +
			"look at.",
			schema(map[string]any{
				"path":   str("Absolute, or relative to /root."),
				"offset": intIn("Byte offset to start at (default 0).", 0, 1<<62),
				"limit":  intIn("Bytes to return (default 20000).", 1, 100000),
			}, "path")},
		{"write_file", "Write a file in the sandbox, replacing it if it exists and creating missing parent " +
			"directories. Use it for code, configs and scripts, rather than echo or heredocs in shell.",
			schema(map[string]any{
				"path":    str("Absolute, or relative to /root."),
				"content": str("The whole file."),
			}, "path", "content")},
		{"list_files", "List a directory in the sandbox: each entry's type (file, dir, link), size in bytes, and name.",
			schema(map[string]any{"path": str("Absolute, or relative to /root (default /root).")})},
		{"start_process", "Start a command in the background and return its process ID at once: for servers, " +
			"builds, long test runs, anything that takes minutes or never ends. It keeps running between your " +
			"calls; its output (stdout and stderr) is kept for process_logs.",
			schema(map[string]any{
				"command": str("The command line to run in the background."),
				"cwd":     str("Directory to run it in (default /root)."),
			}, "command")},
		{"process_logs", "Read a background process's output, a page at a time, and whether it's still running or " +
			"how it exited. Each page ends with the next offset to ask for; when a process is still running, ask " +
			"again later from that offset to see what's new.",
			schema(map[string]any{
				"process_id": str("The ID start_process returned."),
				"offset":     intIn("Byte offset to start at (default 0).", 0, 1<<62),
				"limit":      intIn("Bytes to return (default 20000).", 1, 100000),
			}, "process_id")},
		{"forward_port", "Show the user something you built that runs as a server in the sandbox (a web app, an API, " +
			"generated docs): this makes the server's port reachable on the user's machine and returns the URL to give " +
			"them, like http://127.0.0.1:8000. Start the server first, with start_process; it may listen on localhost or " +
			"on every address, and the sandbox needs no network for this. The URL works for the rest of this session, " +
			"waking the sandbox if it has gone to sleep. It's on the user's own machine only, not on the internet.",
			schema(map[string]any{
				"port": intIn("The port the server listens on inside the sandbox.", 1, 65535),
			}, "port")},
		{"fork", "Copy this sandbox as it is right now (files, installed packages, running processes) into new " +
			"sandboxes, to try alternatives side by side from the same starting point. Returns their IDs. Your " +
			"session stays in this sandbox; each copy needs its own session (another sbx-mcp started with -sandbox " +
			"and the copy's ID).",
			schema(map[string]any{"count": intIn("How many copies (default 1).", 1, 16)})},
		{"browse", "Load a web page in a headless browser inside the sandbox and get its visible text: for " +
			"reading documentation and checking web pages. Set screenshot to also see the page as an image. For " +
			"clicking, typing, or several steps on one page, write a Playwright script and run it with shell. " +
			"Needs a browser sandbox (made with -image browser); private addresses and the cloud metadata " +
			"service are always refused. Long pages are cut, with the full text saved for read_file.",
			schema(map[string]any{
				"url":        str("The page, starting with http:// or https://."),
				"screenshot": map[string]any{"type": "boolean", "description": "Also return a screenshot (default false)."},
			}, "url")},
		{"sandbox_info", "Describe this sandbox: its ID, state, memory and CPUs, whether it has a network and " +
			"which egress policy applies, and what it was forked from. Use it when something about the " +
			"environment surprises you, a refused download say.",
			schema(map[string]any{})},
	}
}

func textResult(t string) Result { return Result{Content: []Content{{Type: "text", Text: t}}} }
func errResult(format string, a ...any) Result {
	return Result{Content: []Content{{Type: "text", Text: fmt.Sprintf(format, a...)}}, IsError: true}
}

func (s *Sandbox) Call(ctx context.Context, name string, raw json.RawMessage) Result {
	var a struct {
		Command    string `json:"command"`
		TimeoutS   int    `json:"timeout_s"`
		Path       string `json:"path"`
		Offset     int64  `json:"offset"`
		Limit      int64  `json:"limit"`
		Content    *string
		Cwd        string `json:"cwd"`
		ProcessID  string `json:"process_id"`
		Count      int    `json:"count"`
		URL        string `json:"url"`
		Screenshot bool   `json:"screenshot"`
		Port       int    `json:"port"`
	}
	var withContent struct {
		Content *string `json:"content"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return errResult("bad arguments for %s: %v", name, err)
	}
	_ = json.Unmarshal(raw, &withContent)
	a.Content = withContent.Content
	switch name {
	case "shell":
		return s.shellTool(ctx, a.Command, a.TimeoutS)
	case "read_file":
		return s.readFile(ctx, a.Path, a.Offset, a.Limit)
	case "write_file":
		if a.Content == nil {
			return errResult("write_file needs content (it may be empty)")
		}
		return s.writeFile(ctx, a.Path, *a.Content)
	case "list_files":
		return s.listFiles(ctx, a.Path)
	case "start_process":
		return s.startProcess(ctx, a.Command, a.Cwd)
	case "process_logs":
		return s.processLogs(ctx, a.ProcessID, a.Offset, a.Limit)
	case "forward_port":
		return s.forwardPort(ctx, a.Port)
	case "fork":
		return s.fork(ctx, a.Count)
	case "browse":
		return s.browse(ctx, a.URL, a.Screenshot)
	case "sandbox_info":
		return s.info(ctx)
	}
	return errResult("no tool %q", name)
}

// abs resolves a path the way the tool descriptions promise.
func abs(p string) string {
	if p == "" {
		return "/root"
	}
	if !path.IsAbs(p) {
		p = path.Join("/root", p)
	}
	return path.Clean(p)
}

// fit keeps a long text's beginning and end, saving all of it to a file in
// the sandbox and saying where, so the model can page through the rest.
func (s *Sandbox) fit(ctx context.Context, kind, text string) string {
	if len(text) <= maxText {
		return text
	}
	s.mu.Lock()
	s.saved++
	file := fmt.Sprintf("%s/%s-%d.txt", s.WorkDir, kind, s.saved)
	s.mu.Unlock()
	where := "the full text is in " + file + ": read_file it with an offset to page through"
	if _, err := s.c.Put(ctx, s.id, file, strings.NewReader(text), client.PutOptions{Mkdirs: true}); err != nil {
		where = "the full text couldn't be saved: " + err.Error()
	}
	head, tail := validPrefix(text[:headText]), validSuffix(text[len(text)-(maxText-headText):])
	return fmt.Sprintf("%s\n\n[... %d bytes in total; %d omitted here; %s ...]\n\n%s",
		head, len(text), len(text)-len(head)-len(tail), where, tail)
}

func validPrefix(s string) string {
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func validSuffix(s string) string {
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[1:]
	}
	return s
}

func (s *Sandbox) shellTool(ctx context.Context, command string, timeoutS int) Result {
	if strings.TrimSpace(command) == "" {
		return errResult("shell needs a command")
	}
	if timeoutS <= 0 {
		timeoutS = 120
	}
	if timeoutS > 1800 {
		timeoutS = 1800
	}
	out, code, timedOut, notice, err := s.sh.Exec(ctx, command, time.Duration(timeoutS)*time.Second)
	if err != nil {
		if gone := s.gone(ctx); gone != "" {
			return errResult("%s", gone)
		}
		return errResult("%s%v", notice, err)
	}
	out = strings.TrimSuffix(out, "\n")
	if code == -1 && strings.HasSuffix(notice, "(exit 1)]\n") { // the shell exited
		return Result{Content: []Content{{Type: "text", Text: s.fit(ctx, "shell", out) + "\n" + strings.TrimSuffix(notice, "\n")}}, IsError: true}
	}
	var tail string
	switch {
	case timedOut:
		tail = fmt.Sprintf("[timed out after %ds and interrupted (Ctrl-C); exit code %d. The output above is what it printed until then. "+
			"If it was waiting for input, it can't get any: use non-interactive flags or a script. For long jobs, use start_process.]", timeoutS, code)
	default:
		tail = fmt.Sprintf("[exit code %d]", code)
		var why []string
		if m := s.exitMeaning(ctx, code); m != "" {
			why = append(why, m)
		}
		if code != 0 {
			if h := s.networkHint(ctx, out); h != "" {
				why = append(why, h)
			}
		}
		if len(why) > 0 {
			tail = fmt.Sprintf("[exit code %d: %s]", code, strings.Join(why, ". "))
		}
	}
	body := s.fit(ctx, "shell", out)
	if body != "" {
		body += "\n"
	}
	return Result{Content: []Content{{Type: "text", Text: notice + body + tail}}, IsError: timedOut}
}

// window keeps bytes [skip, skip+limit) of a stream, and stops after.
type window struct {
	skip, limit int64
	buf         bytes.Buffer
	full        bool
}

func (w *window) Write(p []byte) (int, error) {
	n := len(p)
	if w.skip > 0 {
		if int64(len(p)) <= w.skip {
			w.skip -= int64(len(p))
			return n, nil
		}
		p = p[w.skip:]
		w.skip = 0
	}
	if room := w.limit - int64(w.buf.Len()); int64(len(p)) >= room {
		w.buf.Write(p[:room])
		w.full = true
		return n, errWindowFull
	}
	w.buf.Write(p)
	return n, nil
}

var errWindowFull = fmt.Errorf("enough read")

func pageLimit(limit int64) int64 {
	if limit <= 0 {
		return maxText
	}
	if limit > 100000 {
		return 100000
	}
	return limit
}

var imageTypes = map[string]string{".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp"}

func (s *Sandbox) readFile(ctx context.Context, p string, offset, limit int64) Result {
	p = abs(p)
	st, err := s.c.Stat(ctx, s.id, p)
	if err != nil {
		return s.explainErr(ctx, err, p, "Paths are absolute or relative to /root; list_files shows what's in a directory.")
	}
	if st.IsDir {
		return errResult("%s is a directory: use list_files", p)
	}
	if mime, ok := imageTypes[strings.ToLower(path.Ext(p))]; ok && offset == 0 && st.Size <= 5<<20 {
		var b bytes.Buffer
		if _, err := s.c.Fetch(ctx, s.id, p, &b); err != nil {
			return errResult("%s: %v", p, err)
		}
		return Result{Content: []Content{
			{Type: "image", Data: base64.StdEncoding.EncodeToString(b.Bytes()), MimeType: mime},
			{Type: "text", Text: fmt.Sprintf("%s (%d bytes)", p, st.Size)},
		}}
	}
	if offset < 0 || offset > st.Size {
		return errResult("offset %d is outside %s (%d bytes)", offset, p, st.Size)
	}
	w := &window{skip: offset, limit: pageLimit(limit)}
	if _, err := s.c.Fetch(ctx, s.id, p, w); err != nil && !w.full {
		return errResult("%s: %v", p, err)
	}
	data := w.buf.Bytes()
	if bytes.IndexByte(data, 0) >= 0 {
		return textResult(fmt.Sprintf("%s is a binary file (%d bytes); not shown as text.", p, st.Size))
	}
	end := offset + int64(len(data))
	text := strings.ToValidUTF8(string(data), "\uFFFD")
	if end < st.Size {
		return textResult(fmt.Sprintf("%s\n[bytes %d-%d of %d; next offset %d]", text, offset, end, st.Size, end))
	}
	return textResult(fmt.Sprintf("%s\n[bytes %d-%d of %d: the end of the file]", text, offset, end, st.Size))
}

func (s *Sandbox) writeFile(ctx context.Context, p, content string) Result {
	p = abs(p)
	if _, err := s.c.Put(ctx, s.id, p, strings.NewReader(content), client.PutOptions{Mkdirs: true}); err != nil {
		return s.explainErr(ctx, err, p, "")
	}
	return textResult(fmt.Sprintf("wrote %s (%d bytes)", p, len(content)))
}

func (s *Sandbox) listFiles(ctx context.Context, p string) Result {
	p = abs(p)
	res, err := s.c.ListDir(ctx, s.id, p)
	if err != nil {
		return s.explainErr(ctx, err, p, "Paths are absolute or relative to /root; try list_files on its parent.")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d entries)\n", p, len(res.Entries))
	for _, e := range res.Entries {
		kind, size := "file", fmt.Sprint(e.Size)
		switch {
		case e.IsDir:
			kind, size = "dir ", "-"
		case e.IsSymlink:
			kind = "link"
		}
		fmt.Fprintf(&b, "%s %10s  %s\n", kind, size, e.Name)
	}
	if res.Truncated {
		b.WriteString("[the listing was cut short: the directory has more entries]\n")
	}
	return textResult(s.fit(ctx, "list", b.String()))
}

func (s *Sandbox) startProcess(ctx context.Context, command, cwd string) Result {
	if strings.TrimSpace(command) == "" {
		return errResult("start_process needs a command")
	}
	started, err := s.c.StartProcess(ctx, s.id, api.ProcStartRequest{Args: []string{"/bin/sh", "-c", command}, Dir: abs(cwd)})
	if err != nil {
		return s.explainErr(ctx, err, "starting the process", "Is the cwd a directory that exists?")
	}
	return textResult(fmt.Sprintf("started process %s (pid %d). Read its output with process_logs(process_id=%q).", started.ID, started.PID, started.ID))
}

func (s *Sandbox) processLogs(ctx context.Context, proc string, offset, limit int64) Result {
	if proc == "" {
		return errResult("process_logs needs a process_id")
	}
	info, err := s.c.Process(ctx, s.id, proc)
	if err != nil {
		known := ""
		if list, lerr := s.c.Processes(ctx, s.id); lerr == nil && len(list) > 0 {
			var ids []string
			for _, p := range list {
				ids = append(ids, p.ID)
			}
			known = " This sandbox's processes are: " + strings.Join(ids, ", ") + "."
		}
		return s.explainErr(ctx, err, "process "+proc, "Process IDs come from start_process."+known)
	}
	w := &window{limit: pageLimit(limit)}
	end, err := s.c.Logs(ctx, s.id, proc, offset, false, w)
	if err != nil && !w.full {
		return errResult("process %s's output: %v", proc, err)
	}
	next := end.Next
	if w.full {
		next = offset + int64(w.buf.Len())
	}
	data := strings.ToValidUTF8(w.buf.String(), "\uFFFD")
	state := "running"
	if !info.Running {
		state = fmt.Sprintf("exited with code %d", info.ExitCode)
		if info.Signal != "" {
			state = "killed by " + info.Signal
		}
	}
	var notes []string
	if end.Skipped > 0 {
		notes = append(notes, fmt.Sprintf("%d earlier bytes were no longer kept", end.Skipped))
	}
	// Every page states the next offset, running or not: a caller polling
	// a running process continues from it (without it, a slow process's
	// pages were read twice, Day 22).
	more := "the end of the output so far"
	if w.full {
		more = "more follows"
	}
	notes = append(notes, fmt.Sprintf("bytes %d-%d; %s; next offset %d; the process is %s", offset, next, more, next, state))
	return textResult(fmt.Sprintf("%s\n[%s]", data, strings.Join(notes, "; ")))
}

func (s *Sandbox) fork(ctx context.Context, count int) Result {
	if count <= 0 {
		count = 1
	}
	forks, err := s.c.Fork(ctx, s.id, api.ForkRequest{Count: count})
	if err != nil {
		return s.explainErr(ctx, err, "fork", "")
	}
	var ids []string
	for _, f := range forks {
		ids = append(ids, f.ID)
	}
	return textResult(fmt.Sprintf("forked %s into %d new sandbox(es): %s. This session stays in %s; to work in a copy, start another sbx-mcp with -sandbox and its ID.",
		s.id, len(ids), strings.Join(ids, ", "), s.id))
}

//go:embed browse.py
var browseHelper string

func (s *Sandbox) browse(ctx context.Context, url string, screenshot bool) Result {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return errResult("browse needs an http:// or https:// URL")
	}
	s.mu.Lock()
	up := s.helperUp
	s.saved++
	n := s.saved
	s.mu.Unlock()
	if !up {
		if _, err := s.c.Put(ctx, s.id, s.WorkDir+"/browse.py", strings.NewReader(browseHelper), client.PutOptions{Mkdirs: true}); err != nil {
			return errResult("setting up the browser helper: %v", err)
		}
		s.mu.Lock()
		s.helperUp = true
		s.mu.Unlock()
	}
	out := fmt.Sprintf("%s/browse-%d.json", s.WorkDir, n)
	args := []string{"python3", s.WorkDir + "/browse.py", url, out}
	shot := ""
	if screenshot {
		shot = fmt.Sprintf("%s/shot-%d.png", s.WorkDir, n)
		args = append(args, shot)
	}
	var stderr strings.Builder
	res, err := s.c.Exec(ctx, s.id, client.ExecRequest{Args: args, Stderr: &stderr, Timeout: 90 * time.Second})
	if err != nil || res.Code != 0 {
		return errResult("the browser helper failed (exit %d, %v): %s", res.Code, err, lastLines(stderr.String(), 5))
	}
	var raw bytes.Buffer
	if _, err := s.c.Fetch(ctx, s.id, out, &raw); err != nil {
		return errResult("reading the browser's result: %v", err)
	}
	var page struct {
		Status     int    `json:"status"`
		URL        string `json:"url"`
		Title      string `json:"title"`
		Text       string `json:"text"`
		Screenshot string `json:"screenshot"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(raw.Bytes(), &page); err != nil {
		return errResult("the browser's result wasn't JSON: %v", err)
	}
	switch {
	case page.Error == "no-browser":
		return errResult("this sandbox has no browser (Playwright isn't installed). Browser sandboxes are made with: sbx create -image browser")
	case page.Error != "":
		return errResult("loading %s failed: %s. If it mentions a tunnel or a 403, the egress proxy refused the destination.", url, page.Error)
	}
	text := fmt.Sprintf("%s\nURL: %s (HTTP %d)\n\n%s", page.Title, page.URL, page.Status, s.fit(ctx, "page", strings.TrimSpace(page.Text)))
	result := Result{Content: []Content{{Type: "text", Text: text}}}
	if page.Screenshot != "" {
		var img bytes.Buffer
		if _, err := s.c.Fetch(ctx, s.id, page.Screenshot, &img); err == nil {
			result.Content = append(result.Content, Content{Type: "image", Data: base64.StdEncoding.EncodeToString(img.Bytes()), MimeType: "image/png"})
		}
	}
	return result
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (s *Sandbox) info(ctx context.Context) Result {
	sb, err := s.c.Get(ctx, s.id)
	if err != nil {
		return errResult("%v", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "sandbox %s: %s\nmemory: %d MiB, %d vCPU(s)\n", sb.ID, sb.State, sb.MemMiB, sb.VCPUs)
	switch {
	case sb.NetSlot == 0:
		b.WriteString("network: none\n")
	case sb.EgressPolicy == "browse":
		b.WriteString("network: yes; egress policy browse (the public internet; private and metadata addresses refused)\n")
	default:
		b.WriteString("network: yes; egress policy allowlist (only the proxy's allowed names)\n")
	}
	if sb.ForkedFrom != "" {
		fmt.Fprintf(&b, "forked from: %s\n", sb.ForkedFrom)
	}
	s.mu.Lock()
	ports := make([]int, 0, len(s.forwards))
	for p := range s.forwards {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, p := range ports {
		fmt.Fprintf(&b, "forwarded: port %d → http://%s\n", p, s.forwards[p].Addr())
	}
	s.mu.Unlock()
	return textResult(b.String())
}

// forwardPort serves a port inside the sandbox on this machine, for the
// user to open: what sbx forward does, for as long as the session lasts. The
// same port number here if it's free, so the address the server announces
// is the one to open; any free port if it isn't.
func (s *Sandbox) forwardPort(ctx context.Context, port int) Result {
	if port < 1 || port > 65535 {
		return errResult("forward_port needs the port the server listens on inside the sandbox, between 1 and 65535")
	}
	note := s.notListening(ctx, port) // what's inside as asked, before anything here changes
	s.mu.Lock()
	ln := s.forwards[port]
	if ln == nil {
		var err error
		if ln, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
			ln, err = net.Listen("tcp4", "127.0.0.1:0")
		}
		if err != nil {
			s.mu.Unlock()
			return errResult("opening a port on this machine to forward from: %v", err)
		}
		s.forwards[port] = ln
		go func() { _ = s.c.ServePort(ln, s.id, port, nil) }()
	}
	s.mu.Unlock()
	text := fmt.Sprintf("Port %d in the sandbox is at http://%s on the user's machine: give them that URL to open in a browser. "+
		"It works for the rest of this session, and wakes the sandbox if it sleeps.", port, ln.Addr())
	if note != "" {
		text += " " + note
	}
	return textResult(text)
}

// notListening says so when nothing listens on port inside yet, and what
// does: the URL is handed out either way, but it can't show anything yet.
func (s *Sandbox) notListening(ctx context.Context, port int) string {
	list, err := s.c.Ports(ctx, s.id)
	if err != nil {
		return ""
	}
	seen := map[int]bool{}
	var others []string
	for _, p := range list.Ports {
		if p.Port == port {
			return ""
		}
		if !seen[p.Port] {
			seen[p.Port] = true
			if p.Command != "" {
				others = append(others, fmt.Sprintf("%d (%s)", p.Port, p.Command))
			} else {
				others = append(others, strconv.Itoa(p.Port))
			}
		}
	}
	note := fmt.Sprintf("But nothing is listening on port %d inside the sandbox yet, so for now the page only says that: "+
		"start the server (start_process), and the URL shows it once it listens.", port)
	if len(others) > 0 {
		note += " Listening now: " + strings.Join(others, "; ") + "."
	}
	return note
}
