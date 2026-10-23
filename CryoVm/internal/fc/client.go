// Package fc is a minimal client for the Firecracker API, spoken as HTTP
// over the Unix socket that each Firecracker process exposes.
package fc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type Client struct {
	http *http.Client
}

// NewClient returns a client that sends every request to the Unix socket at
// sock. The host part of the URL is ignored; Firecracker only reads the path.
func NewClient(sock string) *Client {
	return &Client{http: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 5 * time.Second,
	}}
}

type MachineConfig struct {
	VcpuCount  int `json:"vcpu_count"`
	MemSizeMib int `json:"mem_size_mib"`
}

type BootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type Drive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type action struct {
	ActionType string `json:"action_type"`
}

func (c *Client) SetMachineConfig(ctx context.Context, m MachineConfig) error {
	return c.put(ctx, "/machine-config", m)
}

func (c *Client) SetBootSource(ctx context.Context, b BootSource) error {
	return c.put(ctx, "/boot-source", b)
}

func (c *Client) SetDrive(ctx context.Context, d Drive) error {
	return c.put(ctx, "/drives/"+d.DriveID, d)
}

// Start boots the configured microVM.
func (c *Client) Start(ctx context.Context) error {
	return c.put(ctx, "/actions", action{ActionType: "InstanceStart"})
}

// SendCtrlAltDel asks the guest to shut down (x86_64 only). The guest's init
// turns it into a reboot, and reboot=k makes Firecracker exit.
func (c *Client) SendCtrlAltDel(ctx context.Context) error {
	return c.put(ctx, "/actions", action{ActionType: "SendCtrlAltDel"})
}

func (c *Client) put(ctx context.Context, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://localhost"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("PUT %s: %s: %s", path, resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}
