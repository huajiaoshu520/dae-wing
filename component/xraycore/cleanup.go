// SPDX-License-Identifier: AGPL-3.0-only
package xraycore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// cleanup removes only version directories owned by the manager. Preserve both
// the selected executable and the bundled recovery executable, including aliases.
func (m *Manager) cleanup(ctx context.Context) error {
	report(ctx, "cleanup", 0, 0)
	binary, err := m.Binary()
	if err != nil {
		return err
	}
	if _, err = probe(ctx, binary); err != nil {
		return err
	}
	root, err := filepath.Abs(m.dir)
	if err != nil {
		return err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	versions := func(path string) []string {
		result := []string{}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return result
		}
		paths := []string{absolute}
		if real, err := filepath.EvalSymlinks(absolute); err == nil {
			paths = append(paths, real)
		}
		for _, p := range paths {
			for _, r := range []string{root, realRoot} {
				rel, err := filepath.Rel(r, p)
				if err != nil {
					continue
				}
				name := strings.Split(rel, string(filepath.Separator))[0]
				if versionPattern.MatchString(name) {
					result = append(result, name)
				}
			}
		}
		return result
	}
	keep := map[string]bool{}
	for _, v := range versions(binary) {
		keep[v] = true
	}
	if bundled, err := exec.LookPath("xray"); err == nil {
		for _, v := range versions(bundled) {
			keep[v] = true
		}
	}
	m.mu.RLock()
	next := m.state
	m.mu.RUnlock()
	if next.Current.Mode == "managed" {
		keep[next.Current.Version] = true
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return err
	}
	remove := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() && versionPattern.MatchString(entry.Name()) && !keep[entry.Name()] {
			remove[entry.Name()] = true
		}
	}
	clearPrevious := false
	if previous := next.Previous; previous != nil {
		if previous.Mode == "managed" && remove[previous.Version] {
			clearPrevious = true
		}
		if path, err := m.resolve(*previous); err == nil {
			for _, v := range versions(path) {
				if remove[v] {
					clearPrevious = true
				}
			}
		}
	}
	if clearPrevious {
		next.Previous = nil
		// Save before deleting, so a restart cannot resurrect a dangling rollback.
		if err := m.save(next); err != nil {
			return fmt.Errorf("clear old rollback selection: %w", err)
		}
		m.mu.Lock()
		m.state = next
		m.mu.Unlock()
	}
	var failures []error
	for name := range remove {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if err := os.RemoveAll(filepath.Join(m.dir, name)); err != nil {
			failures = append(failures, fmt.Errorf("remove %s: %w", name, err))
		}
	}
	return errors.Join(failures...)
}
