package gvisor

import (
	"strconv"
	"strings"

	"github.com/Crpedeim/sbx/internal/sandbox"
)

// The subset of the OCI runtime spec that runsc needs. Writing it ourselves
// (rather than running `runsc spec` and editing) keeps every field visible.

type ociSpec struct {
	OCIVersion string     `json:"ociVersion"`
	Process    ociProcess `json:"process"`
	Root       ociRoot    `json:"root"`
	Hostname   string     `json:"hostname"`
	Mounts     []ociMount `json:"mounts"`
	Linux      ociLinux   `json:"linux"`
}

type ociProcess struct {
	Terminal bool     `json:"terminal"`
	User     ociUser  `json:"user"`
	Args     []string `json:"args"`
	Env      []string `json:"env"`
	Cwd      string   `json:"cwd"`
}

// hostPidsFor turns "processes inside" into the host's pids.max for the
// sandbox. Day 8 measured gVisor using about 2.2 host threads per process
// inside, on top of about 20 of its own; 3 per process plus 64 leaves room,
// so the limit inside is always reached first and the host limit is only a
// safety net. (Hit the host limit, and gVisor can't make the threads it
// needs: the whole sandbox fails. Hit the limit inside, and just the fork
// fails.)
func hostPidsFor(inside int) int64 { return 64 + 3*int64(inside) }

type ociUser struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type ociRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type ociMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options,omitempty"`
}

type ociLinux struct {
	Namespaces []ociNamespace `json:"namespaces"`
	Resources  *ociResources  `json:"resources,omitempty"`
	// CgroupsPath is where runsc puts the sandbox in the host's cgroup tree.
	// Without it, runsc creates no cgroup, and Resources has no effect.
	CgroupsPath string `json:"cgroupsPath,omitempty"`
}

type ociNamespace struct {
	Type string `json:"type"`
	// Path joins an existing namespace instead of making a new one: for the
	// network namespace the daemon prepared (Day 16).
	Path string `json:"path,omitempty"`
}

// netNSOf returns the network namespace a spec joins, if any.
func netNSOf(spec *ociSpec) string {
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == "network" {
			return ns.Path
		}
	}
	return ""
}

// networkMode is runsc's --network for a sandbox: "sandbox" (gVisor's own
// stack, on the interface in the joined namespace) when it has a prepared
// namespace, "none" (no network at all) otherwise.
func networkMode(spec *ociSpec) string {
	if netNSOf(spec) != "" {
		return "sandbox"
	}
	return "none"
}

type ociResources struct {
	Memory *ociMemory `json:"memory,omitempty"`
	CPU    *ociCPU    `json:"cpu,omitempty"`
	Pids   *ociPids   `json:"pids,omitempty"`
}

type ociMemory struct {
	Limit int64 `json:"limit"`
	// Swap is memory *plus* swap, in OCI's convention. Equal to Limit, it
	// allows no swap at all, so the limit means real memory.
	Swap *int64 `json:"swap,omitempty"`
}

type ociCPU struct {
	Quota  int64  `json:"quota"`
	Period uint64 `json:"period"`
	Cpus   string `json:"cpus,omitempty"` // a cpuset, e.g. "2" or "0,1"
}

type ociPids struct {
	Limit int64 `json:"limit"`
}

// limits says which resource limits to put in a spec. Without a cgroup
// path there are none: runsc would ignore them anyway.
type limits struct {
	cgroupPath string // e.g. "/sbx/<id>"; empty: no limits (rootless)
	cpus       string // the cpuset; empty: any CPU
}

const cpuPeriod = 100_000 // microseconds

// Where the host's agent directory appears inside the sandbox.
const (
	agentMountPoint = "/sbx"
	agentBinary     = "sbx-agent"
	agentSocket     = "agent.sock"
)

// buildSpec turns a sandbox.Spec into an OCI spec.
//
// Resource limits are cgroup settings, so they need a cgroup path; rootless
// mode can't create cgroups, so lim.cgroupPath is empty there and the spec
// carries no limits. (Day 1 set limits without a cgroup path, and runsc
// ignored them: Day 8 found and fixed that.)
//
// With agentDir set, the guest agent is init: agentDir (holding the agent
// binary and the host's listening socket) is bind-mounted read-only at /sbx,
// and the agent dials /sbx/agent.sock. Read-only matters: the sandbox must not
// be able to replace the agent binary on the host. Without agentDir, init
// just sleeps and commands arrive through `runsc exec`.
func buildSpec(s sandbox.Spec, rootfs string, lim limits, agentDir string) ociSpec {
	spec := ociSpec{
		OCIVersion: "1.0.2",
		Process: ociProcess{
			Args: []string{"sleep", "infinity"},
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"HOME=/root",
				"TERM=xterm",
			},
			Cwd: "/",
		},
		Root:     ociRoot{Path: rootfs},
		Hostname: hostnameFor(s.ID),
		Mounts: []ociMount{
			{Destination: "/proc", Type: "proc", Source: "proc"},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
			{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
			{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
		},
		Linux: ociLinux{Namespaces: []ociNamespace{
			{Type: "pid"}, {Type: "network", Path: s.NetNS}, {Type: "ipc"}, {Type: "uts"}, {Type: "mount"},
		}},
	}
	if agentDir != "" {
		spec.Process.Args = []string{
			agentMountPoint + "/" + agentBinary,
			"-id", s.ID,
			"-dial", "unix:" + agentMountPoint + "/" + agentSocket,
		}
		spec.Mounts = append(spec.Mounts, ociMount{
			Destination: agentMountPoint, Type: "bind", Source: agentDir, Options: []string{"bind", "ro"},
		})
	}
	if lim.cgroupPath != "" {
		spec.Linux.CgroupsPath = lim.cgroupPath
		r := &ociResources{}
		if s.MemMiB > 0 {
			limit := int64(s.MemMiB) << 20
			swap := limit
			r.Memory = &ociMemory{Limit: limit, Swap: &swap}
		}
		if s.VCPUs > 0 {
			r.CPU = &ociCPU{Quota: int64(s.VCPUs) * cpuPeriod, Period: cpuPeriod, Cpus: lim.cpus}
		}
		if s.PidsMax > 0 {
			r.Pids = &ociPids{Limit: hostPidsFor(s.PidsMax)}
		}
		spec.Linux.Resources = r
	}
	// The process limit inside the sandbox goes to the agent, which applies
	// RLIMIT_NPROC to everything it starts while staying unlimited itself
	// (on init, the limit would also count the agent's own threads: a fork
	// bomb filling it would kill the agent, and the sandbox with it).
	// gVisor enforces RLIMIT_NPROC even for root (Day 8 measured it), so a
	// fork bomb gets "Resource temporarily unavailable" and the sandbox
	// lives on. No cgroup needed: it applies in rootless mode too.
	if s.PidsMax > 0 && agentDir != "" {
		spec.Process.Args = append(spec.Process.Args, "-child-nproc", strconv.Itoa(s.PidsMax))
	}
	spec.Process.Env = append(spec.Process.Env, s.Env...)
	return spec
}

// hostnameFor names a sandbox's host. IDs from sbxd already start with
// "sbx-"; prefixing them again gave every daemon-made sandbox a hostname
// like "sbx-sbx-1a2b3c4d", unnoticed from Day 5 until Day 14's fork test
// printed one.
func hostnameFor(id string) string {
	if strings.HasPrefix(id, "sbx-") {
		return id
	}
	return "sbx-" + id
}
