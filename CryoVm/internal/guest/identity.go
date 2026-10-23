package guest

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// identity is who the agent is: a sandbox ID and a generation. A fork's
// agent starts out as its source (it IS the source's agent, copied), and the
// host renames it; any restore gets a new generation.
//
// It's published two ways. Files in Config.IdentityDir (sandbox-id,
// generation) always hold the current value: a program can check the
// generation before using random state or secrets, and renew them when it
// changed. And every process the agent starts gets SBX_SANDBOX_ID and
// SBX_GENERATION in its environment: a snapshot of the identity when it
// started, which is why the files matter for programs already running.
type identity struct {
	mu  sync.Mutex
	id  string
	gen string
	dir string
}

func newIdentity(id, dir string) *identity {
	ident := &identity{id: id, gen: newGeneration(), dir: dir}
	ident.publish()
	return ident
}

// newGeneration draws 128 bits from the kernel. In gVisor those come from
// the host at the moment of reading, so clones get different ones.
func newGeneration() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (i *identity) get() (id, gen string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.id, i.gen
}

// set takes a new identity and returns the previous ID. An empty
// generation means: make a fresh one here.
func (i *identity) set(id, gen string) string {
	i.mu.Lock()
	prev := i.id
	i.id = id
	if gen == "" {
		gen = newGeneration()
	}
	i.gen = gen
	i.mu.Unlock()
	i.publish()
	return prev
}

// publish writes the files, each atomically (a temporary file renamed over
// the old one), so a program never reads half an ID.
func (i *identity) publish() {
	if i.dir == "" {
		return
	}
	id, gen := i.get()
	if err := os.MkdirAll(i.dir, 0o755); err != nil {
		return
	}
	for name, value := range map[string]string{"sandbox-id": id, "generation": gen} {
		tmp := filepath.Join(i.dir, "."+name+".tmp")
		if os.WriteFile(tmp, []byte(value+"\n"), 0o644) == nil {
			_ = os.Rename(tmp, filepath.Join(i.dir, name))
		}
	}
}

// env returns base with the identity variables set (replacing any already
// there). A nil base means the agent's own environment.
func (i *identity) env(base []string) []string {
	if base == nil {
		base = os.Environ()
	}
	id, gen := i.get()
	out := make([]string, 0, len(base)+3)
	for _, kv := range base {
		if !strings.HasPrefix(kv, "SBX_SANDBOX_ID=") && !strings.HasPrefix(kv, "SBX_GENERATION=") && !strings.HasPrefix(kv, "SBX_IDENTITY_DIR=") {
			out = append(out, kv)
		}
	}
	out = append(out, "SBX_SANDBOX_ID="+id, "SBX_GENERATION="+gen)
	if i.dir != "" {
		// Where the live values are: the variables above are a snapshot.
		out = append(out, "SBX_IDENTITY_DIR="+i.dir)
	}
	return out
}
