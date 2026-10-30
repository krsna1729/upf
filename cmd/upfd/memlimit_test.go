// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A pod's limit sits on the container's parent as well as on the container,
// and either may be the smaller: the runtime's limit follows the tighter one,
// and a hierarchy with no limit anywhere (or cgroup v1) sets none.
func TestCgroupMemoryMax(t *testing.T) {
	cases := []struct {
		name   string
		self   string
		limits map[string]string // cgroup dir -> memory.max
		want   int64
		where  string
	}{
		{"own limit", "0::/kubepods/pod1/c1\n",
			map[string]string{"/kubepods/pod1/c1": "2147483648\n", "/kubepods/pod1": "max\n"}, 2 << 30, "/kubepods/pod1/c1"},
		{"the pod's is tighter", "0::/kubepods/pod1/c1\n",
			map[string]string{"/kubepods/pod1/c1": "max\n", "/kubepods/pod1": "1073741824\n"}, 1 << 30, "/kubepods/pod1"},
		{"a namespaced container sees its own root", "0::/\n",
			map[string]string{"/": "536870912\n"}, 512 << 20, "/"},
		{"no limit anywhere", "0::/user.slice/x.scope\n",
			map[string]string{"/user.slice/x.scope": "max\n"}, 0, ""},
		{"cgroup v1", "4:memory:/docker/abc\n1:name=systemd:/docker/abc\n",
			map[string]string{"/docker/abc": "1073741824\n"}, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			self := filepath.Join(root, "self-cgroup")
			if err := os.WriteFile(self, []byte(c.self), 0o644); err != nil {
				t.Fatal(err)
			}
			fs := filepath.Join(root, "fs")
			for dir, v := range c.limits {
				if err := os.MkdirAll(filepath.Join(fs, dir), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fs, dir, "memory.max"), []byte(v), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, where, ok := cgroupMemoryMax(self, fs)
			if got != c.want || where != c.where || ok != (c.want > 0) {
				t.Errorf("cgroupMemoryMax = %d, %q, %v; want %d, %q, %v", got, where, ok, c.want, c.where, c.want > 0)
			}
		})
	}
}

// The headroom is a tenth of the limit, and never less than the floor a small
// container needs for the binary and the journal's page cache.
func TestMemoryHeadroom(t *testing.T) {
	if got := memoryHeadroom(3 << 30); got != (3<<30)/100*10 {
		t.Errorf("3 GiB: headroom %d", got)
	}
	if got := memoryHeadroom(128 << 20); got != memoryHeadroomMin {
		t.Errorf("128 MiB: headroom %d, want the floor %d", got, memoryHeadroomMin)
	}
}
