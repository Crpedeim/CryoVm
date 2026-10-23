package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Crpedeim/sbx/internal/api"
)

func procPath(id, proc string, rest string) string {
	return sbPath(id, "/processes/"+url.PathEscape(proc)+rest)
}

func (c *Client) StartProcess(ctx context.Context, id string, req api.ProcStartRequest) (api.ProcStarted, error) {
	var out api.ProcStarted
	err := c.json(ctx, http.MethodPost, sbPath(id, "/processes"), req, &out)
	return out, err
}

func (c *Client) Processes(ctx context.Context, id string) ([]api.ProcInfo, error) {
	var out []api.ProcInfo
	err := c.json(ctx, http.MethodGet, sbPath(id, "/processes"), nil, &out)
	return out, err
}

func (c *Client) Process(ctx context.Context, id, proc string) (api.ProcInfo, error) {
	var out api.ProcInfo
	err := c.json(ctx, http.MethodGet, procPath(id, proc, ""), nil, &out)
	return out, err
}

func (c *Client) Signal(ctx context.Context, id, proc string, sig int) error {
	var out map[string]int
	return c.json(ctx, http.MethodPost, procPath(id, proc, "/signal"), api.SignalRequest{Signal: sig}, &out)
}

// Wait returns when the process exits. Cancelling ctx stops waiting; the
// process is unaffected.
func (c *Client) Wait(ctx context.Context, id, proc string) (api.ProcInfo, error) {
	var out api.ProcInfo
	err := c.json(ctx, http.MethodGet, procPath(id, proc, "/wait"), nil, &out)
	return out, err
}

func (c *Client) RemoveProcess(ctx context.Context, id, proc string) error {
	var out map[string]string
	return c.json(ctx, http.MethodDelete, procPath(id, proc, ""), nil, &out)
}

// Logs copies a process's output to w from offset, and reports where it
// ended (from the response's trailers). With follow, it streams until the
// process has exited, or ctx is cancelled.
func (c *Client) Logs(ctx context.Context, id, proc string, offset int64, follow bool, w io.Writer) (api.LogsEnd, error) {
	q := url.Values{"offset": {strconv.FormatInt(offset, 10)}}
	if follow {
		q.Set("follow", "1")
	}
	resp, err := c.do(ctx, http.MethodGet, procPath(id, proc, "/logs?"+q.Encode()), nil)
	if err != nil {
		return api.LogsEnd{}, err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(w, resp.Body); err != nil {
		return api.LogsEnd{}, err
	}
	if msg := resp.Trailer.Get(api.TrailerError); msg != "" {
		return api.LogsEnd{}, fmt.Errorf("logs failed midway: %s", msg)
	}
	next, err := strconv.ParseInt(resp.Trailer.Get(api.TrailerNextOffset), 10, 64)
	if err != nil {
		return api.LogsEnd{}, fmt.Errorf("logs ended without a next offset")
	}
	skipped, _ := strconv.ParseInt(resp.Trailer.Get(api.TrailerSkipped), 10, 64)
	exited, _ := strconv.ParseBool(resp.Trailer.Get(api.TrailerExited))
	return api.LogsEnd{Next: next, Skipped: skipped, Exited: exited}, nil
}
