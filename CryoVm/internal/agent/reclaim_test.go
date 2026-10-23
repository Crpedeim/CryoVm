package agent

import (
	"testing"
	"time"
)

func TestReclaimKillsTheBiggestProcessOnly(t *testing.T) {
	_, c, _ := connectedWith(t, nil)
	small := startProc(t, c, "sleep", "31.5")
	// About 60 MB held in a shell variable (tr turns the zeros into 'a's,
	// because a shell variable can't hold NUL bytes).
	big := startProc(t, c, "sh", "-c", `x=$(head -c 60000000 /dev/zero | tr "\0" a); echo held; sleep 30`)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if out, _ := logsOf(t, c, big, 0); out == "held\n" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	res, err := c.Reclaim(wait(t))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Killed || res.Command != "sh" || res.RSS < 50<<20 {
		t.Fatalf("reclaim picked %+v, want the ~60 MB sh", res)
	}
	t.Logf("reclaim killed %s (pid %d, %d MiB)", res.Command, res.PID, res.RSS>>20)
	if info, _ := c.Wait(wait(t), big); info.Signal != "killed" {
		t.Fatalf("the big process should be gone: %+v", info)
	}
	list, _ := c.Processes(wait(t))
	for _, p := range list {
		if p.ID == small && !p.Running {
			t.Fatal("reclaim killed the small process too")
		}
	}
	_ = c.Signal(wait(t), small, 9)
}

// With nothing but the agent, there is nothing to kill: and the agent never
// picks itself (or, in tests, the test binary it runs inside).
func TestReclaimWithNothingToKill(t *testing.T) {
	_, c, _ := connectedWith(t, nil)
	res, err := c.Reclaim(wait(t))
	if err != nil || res.Killed {
		t.Fatalf("reclaim with no processes: %+v %v", res, err)
	}
}
