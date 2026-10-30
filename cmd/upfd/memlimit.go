// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"log/slog"
	"os"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
)

// The Go runtime's soft memory limit, when the operator set none: the cgroup's
// hard limit (memory.max) less a headroom for what the cgroup charges and the
// runtime does not count -- the binary's mapped pages, the page cache of the
// checkpoint journal's writes. Without it the heap goal is twice the live heap
// (GOGC=100) whatever the cgroup allows, and a burst of garbage on top of a
// million sessions' live heap is an OOM kill rather than an earlier collection.
const (
	memoryHeadroomMin      = 32 << 20 // bytes
	memoryHeadroomFraction = 10       // percent of memory.max
)

// applyMemoryLimit sets the runtime's limit from the cgroup this process runs
// in. GOMEMLIMIT in the environment is the operator's own decision and wins
// (the runtime has already applied it); so does a cgroup without a limit.
func applyMemoryLimit(log *slog.Logger) {
	if v := os.Getenv("GOMEMLIMIT"); v != "" {
		log.Info("memory limit from GOMEMLIMIT", "GOMEMLIMIT", v)
		return
	}
	cgMax, dir, ok := cgroupMemoryMax("/proc/self/cgroup", "/sys/fs/cgroup")
	if !ok {
		return
	}
	limit := cgMax - memoryHeadroom(cgMax)
	debug.SetMemoryLimit(limit)
	log.Info("memory limit from the cgroup", "cgroup", dir, "memory_max", cgMax, "go_memory_limit", limit)
}

// memoryHeadroom is what the runtime's limit leaves below memory.max.
func memoryHeadroom(memoryMax int64) int64 {
	return max(memoryHeadroomMin, memoryMax/100*memoryHeadroomFraction)
}

// cgroupMemoryMax is the smallest memory.max of the cgroup v2 hierarchy this
// process is in, from its own cgroup up to the root: a Kubernetes pod limits
// its containers' parent as well as each container. It reports false on cgroup
// v1, outside a cgroup, or where no level has a limit.
func cgroupMemoryMax(selfCgroup, root string) (int64, string, bool) {
	f, err := os.Open(selfCgroup)
	if err != nil {
		return 0, "", false
	}
	defer f.Close()
	var rel string
	found := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// The v2 entry is the only one with hierarchy id 0 and no controllers.
		if p, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			rel, found = p, true
			break
		}
	}
	if !found {
		return 0, "", false
	}
	var best int64
	var where string
	for dir := path.Clean("/" + rel); ; dir = path.Dir(dir) {
		b, err := os.ReadFile(path.Join(root, dir, "memory.max"))
		if err == nil {
			v := strings.TrimSpace(string(b))
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 && (best == 0 || n < best) {
				best, where = n, dir
			}
		}
		if dir == "/" {
			break
		}
	}
	return best, where, best > 0
}
