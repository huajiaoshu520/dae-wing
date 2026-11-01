// SPDX-License-Identifier: AGPL-3.0-only
package xraycore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupKeepsCurrentAndUnownedFiles(t *testing.T) {
	m := &Manager{}
	if err := m.Configure(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v26.10.21", "v26.10.31"} {
		dir := filepath.Join(m.dir, version)
		os.MkdirAll(dir, 0700)
		fakeCore(t, dir, version[1:])
	}
	m.state = state{Current: Selection{Mode: "managed", Version: "v26.10.31"}, Previous: &Selection{Mode: "managed", Version: "v26.10.21"}}
	unowned := filepath.Join(m.dir, "notes")
	os.Mkdir(unowned, 0700)
	outside := t.TempDir()
	marker := filepath.Join(outside, "keep")
	os.WriteFile(marker, []byte("keep"), 0600)
	if err := os.Symlink(outside, filepath.Join(m.dir, "v26.9.30")); err != nil {
		t.Fatal(err)
	}
	if err := m.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "v26.10.21")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old core was kept", err)
	}
	for _, path := range []string{unowned, marker, filepath.Join(m.dir, "v26.10.31", "xray")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(path, err)
		}
	}
	if m.state.Previous != nil {
		t.Fatal("rollback still references deleted core")
	}
	n := &Manager{}
	if err := n.Configure(filepath.Dir(m.dir)); err != nil {
		t.Fatal(err)
	}
	if n.state.Previous != nil {
		t.Fatal("restart restored deleted rollback target")
	}
}

func TestCleanupPreservesBundledRecoveryAndActiveSymlink(t *testing.T) {
	m := &Manager{}
	if err := m.Configure(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v26.10.21", "v26.10.31", "v26.9.30"} {
		dir := filepath.Join(m.dir, version)
		os.MkdirAll(dir, 0700)
		fakeCore(t, dir, version[1:])
	}
	// The bundled executable can be an alias into a version directory.
	t.Setenv("PATH", filepath.Join(m.dir, "v26.10.21"))
	alias := filepath.Join(t.TempDir(), "selected-xray")
	os.Symlink(filepath.Join(m.dir, "v26.10.31", "xray"), alias)
	m.state = state{Current: Selection{Mode: "system", Path: alias}, Previous: &Selection{Mode: "bundled"}}
	if err := m.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v26.10.21", "v26.10.31"} {
		if _, err := os.Stat(filepath.Join(m.dir, version, "xray")); err != nil {
			t.Fatal(version, err)
		}
	}
	if _, err := os.Stat(filepath.Join(m.dir, "v26.9.30")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unused version kept", err)
	}
	if m.state.Previous == nil {
		t.Fatal("valid bundled rollback was removed")
	}
}

func TestCleanupRejectsMissingActiveCore(t *testing.T) {
	m := &Manager{}
	if err := m.Configure(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(m.dir, "v26.10.21")
	os.MkdirAll(old, 0700)
	fakeCore(t, old, "26.10.21")
	m.state.Current = Selection{Mode: "system", Path: "/nonexistent/xray"}
	if err := m.cleanup(context.Background()); err == nil {
		t.Fatal("cleaned with an unusable selected core")
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatal("deleted recovery before validation", err)
	}
}
