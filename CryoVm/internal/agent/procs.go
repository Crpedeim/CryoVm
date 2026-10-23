package agent

import (
	"context"
	"fmt"
	"io"

	"github.com/Crpedeim/sbx/internal/agentproto"
)

type ProcStart = agentproto.ProcStart
type ProcInfo = agentproto.ProcInfo
type LogsEnd = agentproto.LogsEnd

// StartProcess launches a background process in the sandbox and returns at
// once. The process outlives this connection.
func (c *Conn) StartProcess(ctx context.Context, req ProcStart) (agentproto.ProcStarted, error) {
	var out agentproto.ProcStarted
	label := ""
	if len(req.Args) > 0 {
		label = req.Args[0]
	}
	err := c.call(ctx, "start", agentproto.TypeProcStart, agentproto.TypeProcStarted, label, req, &out)
	return out, err
}

// Processes lists background processes, running and exited, oldest first.
func (c *Conn) Processes(ctx context.Context) ([]ProcInfo, error) {
	var out agentproto.ProcList
	err := c.call(ctx, "list processes", agentproto.TypeProcList, agentproto.TypeProcListed, "", nil, &out)
	return out.Processes, err
}

// Signal sends a signal to a process's whole group.
func (c *Conn) Signal(ctx context.Context, id string, sig int) error {
	return c.call(ctx, "signal", agentproto.TypeProcSignal, agentproto.TypeProcSignaled, id, agentproto.ProcSignal{ID: id, Signal: sig}, nil)
}

// Wait blocks until the process exits, or ctx ends. Ending the wait never
// affects the process.
func (c *Conn) Wait(ctx context.Context, id string) (ProcInfo, error) {
	var out ProcInfo
	err := c.call(ctx, "wait", agentproto.TypeProcWait, agentproto.TypeProcExited, id, agentproto.ProcRef{ID: id}, &out)
	return out, err
}

// RemoveProcess forgets an exited process and deletes its logs.
func (c *Conn) RemoveProcess(ctx context.Context, id string) error {
	return c.call(ctx, "remove", agentproto.TypeProcRemove, agentproto.TypeProcRemoved, id, agentproto.ProcRef{ID: id}, nil)
}

// Logs copies a process's output to w, from offset. Without follow, it
// returns once it reaches the end of what's been written so far. With
// follow, it keeps streaming until the process has exited and its output
// has drained. Each chunk is acknowledged after w accepts it, so a slow w
// slows the agent down. The result's Next is where to resume next time.
func (c *Conn) Logs(ctx context.Context, id string, offset int64, follow bool, w io.Writer) (LogsEnd, error) {
	rid, p, err := c.register(2*agentproto.Window + 4)
	if err != nil {
		return LogsEnd{}, err
	}
	defer c.unregister(rid, p)
	req, _ := agentproto.New(agentproto.TypeProcLogs, rid, agentproto.ProcLogs{ID: id, Offset: offset, Follow: follow})
	if err := c.send(req); err != nil {
		return LogsEnd{}, err
	}
	for {
		select {
		case f := <-p.ch:
			switch f.Type {
			case agentproto.TypeChunk:
				var ch agentproto.Chunk
				if err := f.Decode(&ch); err != nil {
					return LogsEnd{}, err
				}
				if _, err := w.Write(ch.Data); err != nil {
					c.cancelTransfer(rid, p)
					return LogsEnd{}, fmt.Errorf("logs %s: writing: %w", id, err)
				}
				ack, _ := agentproto.New(agentproto.TypeAck, rid, nil)
				if err := c.send(ack); err != nil {
					return LogsEnd{}, err
				}
			case agentproto.TypeLogsEnd:
				var end LogsEnd
				err := f.Decode(&end)
				return end, err
			case agentproto.TypeError:
				return LogsEnd{}, fileErr("logs", id, f)
			}
		case <-ctx.Done():
			c.cancelTransfer(rid, p)
			return LogsEnd{}, ctx.Err()
		case <-c.done:
			return LogsEnd{}, ErrClosed
		}
	}
}

// Reclaim asks the agent to kill the process using the most memory: the
// memory guard's last resort before the kernel's OOM killer, which would
// take the whole sandbox down.
func (c *Conn) Reclaim(ctx context.Context) (agentproto.Reclaimed, error) {
	var out agentproto.Reclaimed
	err := c.call(ctx, "reclaim", agentproto.TypeReclaim, agentproto.TypeReclaimed, "", nil, &out)
	return out, err
}

// Quiesce asks the agent to let go of this connection before a checkpoint,
// and waits until it has: the connection's end-of-file from the agent's
// side is the proof that no connection is open inside the sandbox.
func (c *Conn) Quiesce(ctx context.Context) error {
	if err := c.call(ctx, "quiesce", agentproto.TypeQuiesce, agentproto.TypeQuiesced, "", nil, nil); err != nil {
		return err
	}
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("agent acknowledged the quiesce but kept its connection: %w", ctx.Err())
	}
}

// SetIdentity tells the agent who it is now (Day 15). It answers with the
// ID it had before.
func (c *Conn) SetIdentity(ctx context.Context, id, generation string) (agentproto.IdentityAck, error) {
	var ack agentproto.IdentityAck
	err := c.call(ctx, "identity", agentproto.TypeIdentity, agentproto.TypeIdentityAck, "",
		agentproto.Identity{SandboxID: id, Generation: generation}, &ack)
	return ack, err
}
