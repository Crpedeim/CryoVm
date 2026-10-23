# sbx benchmarks

Run 2026-10-22 21:00 IST, 18m4s long. Every number is measured through the daemon's API, on the machine described below.

## The resume entry

- …resuming sandboxes with running processes and terminals intact from S3-compatible storage in **86 ms** (p50), within **36 ms** of starting an empty one (**50 ms**); **323 ms** for one holding 128 MiB of memory.
  - The resume is p50 from the resume call to the first exec returning, the image downloaded and SHA-256-verified first; the cold start is p50 from the create call to the first exec of an empty sandbox. On gVisor there is no guest kernel to boot, so an empty sandbox starts fast: resume's value is that everything comes back, not that it's quicker.
- …cloning an environment into **16** copies in **1079 ms** at **19.9 MiB** per sandbox.
  - p50 from the fork call until all 16 clones answer an exec; per sandbox is each clone's PSS with all 16 running, which shares runsc's code pages among them. One more clone's own memory (its cgroup's count) is 18.6 MiB.

## The machine

| | at the start | at the end |
| --- | --- | --- |
| CPU | AMD Ryzen 5 9600X 6-Core Processor (6 CPUs) |  |
| Memory | 23137 MiB total, 18360 available | 16874 available |
| Virtualized | yes: this host is itself a VM (hypervisor flag); systemd-detect-virt: oracle |  |
| Kernel | 7.0.0-38-generic |  |
| CPU governor | not exposed (no cpufreq: typical of a VM) | not exposed (no cpufreq: typical of a VM) |
| Load average | 1.52 1.60 10.71 2/2717 834625 | 31.05 64.10 51.08 3/5122 409533 |
| Busiest processes (%CPU) | 42.8 gvisor_sentry; 8.3 sbxd; 4.3 code; 2.8 code; 2.5 gnome-shell | 41.3 sbx-bench; 2.5 gnome-shell; 1.4 code; 1.1 code; 1.0 sbxd |
| gVisor | runsc version release-20261005.0 |  |
| Platform | systrap (runsc's default; sbx passes no --platform) |  |
| Object store | SeaweedFS: version 30GB 4.48 530be3e37337488ecc34d58441e0bc476e121c93 linux amd64 at http://127.0.0.1:8333 |  |
| Checkpoint filesystem | ext4 (mounted at /) |  |
| Checkpoint image I/O | auto: O_DIRECT for a sandbox holding more than 40% of its memory limit (this runsc offers it: checkpoint true, restore true) |  |
| fsync on that filesystem (4 KiB, p50) | 0.7 ms |  |
| Go, sbx commit | go1.22.2, unknown |  |

## Cold start: create call → first exec returns

Load at the start: 1.52 1.60 10.71. One warm-up run first, not counted: 57.9 ms.

| | n | p50 ms | p99 ms | min | max | mean |
| --- | --- | --- | --- | --- | --- | --- |
| base image, empty | 20 | **49.6** | 92.0 | 46.8 | 92.0 | 53.9 |

## Snapshot and resume, by memory in use

Each sandbox holds a workload: a counting shell loop (0 MiB), or a Python process that has written to every page of a buffer. Snapshot is the checkpoint call until the image is saved (local disk) or its manifest is committed (object store); the sandbox is paused. Resume is the resume call until the first exec returns; from the object store the local copy was deleted after each upload, so every resume downloads and verifies the image first. Each row: one warm-up round, then the timed ones.

| memory in use | where | image MiB | uploaded MiB | snapshot p50 ms | p99 | resume p50 ms | p99 | n | load at the start |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 MiB | local disk | 1.4 | — | **68.4** | 143.1 | **74.1** | 113.5 | 20 | 1.52 1.60 10.71 |
| 0 MiB | object store | 1.4 | 5.1 | **115.7** | 153.3 | **85.8** | 145.0 | 20 | 1.40 1.57 10.65 |
| 64 MiB | local disk | 68.1 | — | **143.8** | 221.6 | **128.8** | 145.7 | 20 | 1.37 1.56 10.60 |
| 64 MiB | object store | 68.0 | 71.8 | **362.7** | 392.6 | **196.7** | 210.1 | 20 | 1.66 1.62 10.57 |
| 128 MiB | local disk | 132.1 | — | **156.8** | 214.0 | **148.5** | 173.8 | 20 | 2.88 1.90 10.52 |
| 128 MiB | object store | 132.1 | 135.8 | **523.0** | 665.3 | **322.6** | 363.4 | 20 | 2.73 1.89 10.47 |

What goes to the store is the image plus the agent binary every image carries (Day 11).

## Checkpoint I/O: buffered vs O_DIRECT

Local disk, at sizes where buffered I/O is safe. A buffered image's page cache is charged to the sandbox's own memory limit, which killed a sandbox holding 128 of 256 MiB; O_DIRECT avoids that, at a cost measured here. The default, auto, uses O_DIRECT only above 40% of a sandbox's limit.

| memory in use | snapshot p50, buffered | snapshot p50, O_DIRECT | resume p50, buffered | resume p50, O_DIRECT |
| --- | --- | --- | --- | --- |
| 0 MiB | 47.9 ms | 69.9 ms | 66.8 ms | 69.3 ms |
| 64 MiB | 119.7 ms | 149.6 ms | 112.9 ms | 111.1 ms |

## Fork: fork call → every clone answers an exec

From a running sandbox (so each fork includes a snapshot of the source); the clones are made in parallel, at most one per CPU, and queried in parallel. Load at the start: 3.23 2.12 10.22.

| N | runs | p50 ms | p99 ms | per clone (p50 / N) |
| --- | --- | --- | --- | --- |
| 1 | 5 | **129.8** | 148.4 | 129.8 |
| 2 | 5 | **187.0** | 241.6 | 93.5 |
| 4 | 5 | **275.7** | 311.0 | 68.9 |
| 8 | 5 | **521.4** | 530.6 | 65.2 |
| 16 | 5 | **1079.4** | 1105.5 | 67.5 |

Where each clone's time goes: the p50 of each phase, per clone, as the daemon logged it. A phase that grows with N is where the clones wait on each other.

| N | registry ms | network ms | restore ms | agent ms | finish ms |
| --- | --- | --- | --- | --- | --- |
| 1 | 0 | 0 | 70 | 0 | 1 |
| 2 | 0 | 0 | 111 | 1 | 2 |
| 4 | 0 | 0 | 172 | 6 | 3 |
| 8 | 0 | 0 | 248 | 7 | 7 |
| 16 | 0 | 0 | 260 | 11 | 7 |

## Memory per sandbox, as clone count grows

PSS of every process in each clone's cgroup, with all N clones running, and the cgroup's own count. A flat cgroup count means the clones share none of their sandbox memory (as Day 14 found); PSS falls as N grows because runsc's own code pages are shared, and PSS divides them among more processes.

| N | PSS per clone, MiB | cgroup memory per clone, MiB | the source's PSS, MiB |
| --- | --- | --- | --- |
| 1 | **21.9** | 18.9 | 23.8 |
| 2 | **21.8** | 19.4 | 29.1 |
| 4 | **20.8** | 19.0 | 29.0 |
| 8 | **20.3** | 18.9 | 29.4 |
| 16 | **19.9** | 18.6 | 29.6 |

## Terminal round trip: keystroke sent → echoed byte received

"Just resumed" is the first keystroke after the sandbox was paused, resumed and its shell session reattached. Load at the start: 3.34 2.26 10.02.

| | n | p50 ms | p99 ms | min | max | mean |
| --- | --- | --- | --- | --- | --- | --- |
| running | 200 | **1.1** | 12.6 | 0.3 | 17.7 | 1.5 |
| just resumed | 20 | **1.0** | 4.0 | 0.5 | 4.0 | 1.3 |

## Density: sandboxes running at once

Measured last, since it loads the machine most. Sandboxes were created, each answering an exec (and, for the browser image, running Chromium with a page open), until a share of the memory available at the start was used: filling the host for real could take everything else on it down. The last column extrapolates, from the memory each one actually took, to all of the memory that was available: an estimate, by memory alone.

| sandboxes | running (measured) | stopped at | PSS each, MiB | available memory used each, MiB | create → ready p50 ms | load at the start | extrapolated to the host's limit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| base, idle | **500** | the cap of 500 sandboxes | 16.6 | 11.6 | 372.7 | 3.07 2.24 9.92 | ~1502 |
| browser, Chromium running a page | **41** | the budget: 50% of the memory available at the start | 316.1 | 208.5 | 1139.6 | 65.98 75.47 53.72 | ~80 |

## Method

- p50 and p99 use the nearest rank: with n samples, p99 is the ceil(0.99 n)-th smallest, so **for n ≤ 100 it is the largest sample**: a worst case seen, not a stable tail.
- Cold start, snapshot and resume each run one warm-up round first, reported but not counted.
- Each measurement runs on private daemons, separate from any sbxd service, with that service's defaults (1 vCPU, 256 MiB, browser image 2048 MiB). Sandboxes never idle-pause during the run. Density runs last, and the load average at the start of each measurement is shown with it.
- Compare these numbers only with others from the same setup: Day 14 saw file transfers swing between 30 and 130 MB/s from one day to the next on this machine with no code change.
