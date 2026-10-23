package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/Crpedeim/sbx/internal/agentproto"
	"github.com/Crpedeim/sbx/internal/api"
)

type ShellOptions struct {
	SessionID  string // empty: a new session
	Cols, Rows uint16
	Command    []string
	Env        []string
	Dir        string
}

// ShellEnd says how the attachment ended: detached (the session lives on)
// or exited (the shell is gone).
type ShellEnd struct {
	Detached bool
	Reason   string
	Exited   bool
	Code     int
	Signal   string
}

// ShellConn is a live attachment to a session, over an upgraded connection.
type ShellConn struct {
	SessionID string
	Created   bool

	rwc io.ReadWriteCloser
	br  *bufio.Reader
	mu  sync.Mutex
}

// Shell opens or attaches to a terminal session. The HTTP request asks to
// upgrade; once the daemon answers 101, the response body becomes a
// two-way stream of frames.
func (c *Client) Shell(ctx context.Context, sandboxID string, opts ShellOptions) (*ShellConn, error) {
	q := url.Values{}
	if opts.SessionID != "" {
		q.Set("session", opts.SessionID)
	}
	if opts.Cols > 0 && opts.Rows > 0 {
		q.Set("cols", strconv.Itoa(int(opts.Cols)))
		q.Set("rows", strconv.Itoa(int(opts.Rows)))
	}
	for _, a := range opts.Command {
		q.Add("cmd", a)
	}
	for _, e := range opts.Env {
		q.Add("env", e)
	}
	if opts.Dir != "" {
		q.Set("dir", opts.Dir)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+sbPath(sandboxID, "/shell?"+q.Encode()), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", api.ShellProtocol)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sbxd unreachable (is it running?): %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		return nil, decodeErr(resp)
	}
	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		return nil, errors.New("upgraded connection is not writable")
	}
	s := &ShellConn{rwc: rwc, br: bufio.NewReader(rwc)}
	first, err := agentproto.Read(s.br)
	if err != nil {
		rwc.Close()
		return nil, err
	}
	switch first.Type {
	case agentproto.TypeShellReady:
		var r agentproto.ShellReady
		if err := first.Decode(&r); err != nil {
			rwc.Close()
			return nil, err
		}
		s.SessionID, s.Created = r.SessionID, r.Created
		return s, nil
	case agentproto.TypeError:
		rwc.Close()
		return nil, streamErr(first)
	default:
		rwc.Close()
		return nil, fmt.Errorf("shell: unexpected %q frame", first.Type)
	}
}

func streamErr(m agentproto.Message) error {
	var b agentproto.ErrorBody
	_ = m.Decode(&b)
	return &APIError{Status: http.StatusOK, Code: b.Code, Message: b.Message}
}

func (s *ShellConn) send(typ string, body any) error {
	m, err := agentproto.New(typ, 0, body)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return agentproto.Write(s.rwc, m)
}

// Write sends keystrokes.
func (s *ShellConn) Write(b []byte) (int, error) {
	for sent := 0; sent < len(b); {
		chunk := b[sent:min(len(b), sent+32<<10)]
		if err := s.send(agentproto.TypePtyIn, agentproto.Chunk{Data: chunk}); err != nil {
			return sent, err
		}
		sent += len(chunk)
	}
	return len(b), nil
}

func (s *ShellConn) Resize(cols, rows uint16) error {
	return s.send(agentproto.TypeResize, agentproto.Resize{Cols: cols, Rows: rows})
}

// Detach leaves the session running; Run returns when the daemon confirms.
func (s *ShellConn) Detach() error { return s.send(agentproto.TypeDetach, nil) }

// Run copies output to w until the attachment ends.
func (s *ShellConn) Run(w io.Writer) (ShellEnd, error) {
	for {
		m, err := agentproto.Read(s.br)
		if err != nil {
			return ShellEnd{}, fmt.Errorf("shell connection lost: %w", err)
		}
		switch m.Type {
		case agentproto.TypePtyOut:
			var c agentproto.Chunk
			if m.Decode(&c) == nil {
				if _, err := w.Write(c.Data); err != nil {
					return ShellEnd{}, err
				}
			}
		case agentproto.TypeDetached:
			var d agentproto.Detached
			_ = m.Decode(&d)
			return ShellEnd{Detached: true, Reason: d.Reason}, nil
		case agentproto.TypeShellExit:
			var e agentproto.Exit
			_ = m.Decode(&e)
			return ShellEnd{Exited: true, Code: e.Code, Signal: e.Signal}, nil
		case agentproto.TypeError:
			return ShellEnd{}, streamErr(m)
		}
	}
}

func (s *ShellConn) Close() error { return s.rwc.Close() }

type SessionInfo struct {
	ID       string   `json:"id"`
	Command  []string `json:"command"`
	Attached bool     `json:"attached"`
	Exited   bool     `json:"exited"`
}

func (c *Client) Sessions(ctx context.Context, sandboxID string) ([]SessionInfo, error) {
	var out struct {
		Sessions []SessionInfo `json:"sessions"`
	}
	err := c.json(ctx, http.MethodGet, sbPath(sandboxID, "/sessions"), nil, &out)
	return out.Sessions, err
}

func (c *Client) KillSession(ctx context.Context, sandboxID, sessionID string) error {
	var out map[string]string
	return c.json(ctx, http.MethodDelete, sbPath(sandboxID, "/sessions/"+url.PathEscape(sessionID)), nil, &out)
}
