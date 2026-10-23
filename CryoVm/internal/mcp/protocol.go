// Package mcp is sbx's Model Context Protocol server (Day 21): the tools an
// AI agent uses to work in one sandbox.
//
// MCP is JSON-RPC 2.0. Over stdio, each message is one line of JSON: the
// client (Claude Code, say) starts sbx-mcp as a subprocess and writes
// requests to its stdin; the server answers on stdout. A tools-only server
// needs four methods:
//
//	initialize   agree on a protocol version, say what the server offers
//	tools/list   name, describe and give a JSON Schema for each tool
//	tools/call   run one
//	ping         answer
//
// Stdout carries protocol messages and nothing else: a stray log line there
// corrupts the stream, so everything else goes to stderr.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Versions this server speaks, newest first. The client proposes one; if
// it's here we answer with it, otherwise with our newest, and the client
// decides whether it can live with that.
var protocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent for a notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC's error codes.
const (
	errParse          = -32700
	errInvalidRequest = -32600
	errNoMethod       = -32601
	errInvalidParams  = -32602
)

// Content is one piece of a tool's result: text, or an image (base64).
type Content struct {
	Type     string `json:"type"` // "text" or "image"
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

// Result is what a tool call returns. IsError marks a tool that ran and
// failed (the model should read why), as opposed to a protocol error.
type Result struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Tool is a tool's listing: its name, a description written for a model,
// and a JSON Schema for its arguments.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Handler runs the tools.
type Handler interface {
	Tools() []Tool
	Call(ctx context.Context, name string, args json.RawMessage) Result
	Instructions() string
}

// Serve reads requests from r and writes responses to w until r ends.
// Requests run concurrently, so a long tool call doesn't block a ping;
// writes are serialized; a notifications/cancelled cancels its call.
func Serve(ctx context.Context, h Handler, r io.Reader, w io.Writer, version string) error {
	var wmu sync.Mutex
	send := func(resp response) {
		resp.JSONRPC = "2.0"
		b, err := json.Marshal(resp)
		if err != nil {
			b, _ = json.Marshal(response{JSONRPC: "2.0", ID: resp.ID, Error: &rpcError{Code: -32603, Message: err.Error()}})
		}
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = w.Write(append(b, '\n'))
	}
	var cmu sync.Mutex
	inflight := map[string]context.CancelFunc{}
	var running sync.WaitGroup
	defer running.Wait()

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024) // a write_file can be large
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			send(response{ID: json.RawMessage("null"), Error: &rpcError{Code: errParse, Message: "not JSON: " + err.Error()}})
			continue
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			if len(req.ID) > 0 {
				send(response{ID: req.ID, Error: &rpcError{Code: errInvalidRequest, Message: "not a JSON-RPC 2.0 request"}})
			}
			continue
		}
		if len(req.ID) == 0 { // a notification: nothing to answer
			if req.Method == "notifications/cancelled" {
				var p struct {
					RequestID json.RawMessage `json:"requestId"`
				}
				if json.Unmarshal(req.Params, &p) == nil {
					cmu.Lock()
					if cancel := inflight[string(p.RequestID)]; cancel != nil {
						cancel()
					}
					cmu.Unlock()
				}
			}
			continue
		}
		rctx, cancel := context.WithCancel(ctx)
		key := string(req.ID)
		cmu.Lock()
		inflight[key] = cancel
		cmu.Unlock()
		running.Add(1)
		go func(req request) {
			defer running.Done()
			defer func() {
				cmu.Lock()
				delete(inflight, key)
				cmu.Unlock()
				cancel()
			}()
			result, rerr := dispatch(rctx, h, req, version)
			if rctx.Err() != nil && ctx.Err() == nil {
				return // cancelled by the client: it no longer wants an answer
			}
			send(response{ID: req.ID, Result: result, Error: rerr})
		}(req)
	}
	return sc.Err()
}

func dispatch(ctx context.Context, h Handler, req request, version string) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		agreed := protocolVersions[0]
		for _, v := range protocolVersions {
			if v == p.ProtocolVersion {
				agreed = v
			}
		}
		return map[string]any{
			"protocolVersion": agreed,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "sbx", "version": version},
			"instructions":    h.Instructions(),
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": h.Tools()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return nil, &rpcError{Code: errInvalidParams, Message: "tools/call needs a name"}
		}
		for _, t := range h.Tools() {
			if t.Name == p.Name {
				if len(p.Arguments) == 0 {
					p.Arguments = json.RawMessage("{}")
				}
				return h.Call(ctx, p.Name, p.Arguments), nil
			}
		}
		return nil, &rpcError{Code: errInvalidParams, Message: fmt.Sprintf("no tool %q", p.Name)}
	default:
		return nil, &rpcError{Code: errNoMethod, Message: "no method " + req.Method}
	}
}
