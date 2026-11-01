// SPDX-License-Identifier: AGPL-3.0-only
// Package xraycore manages persisted Xray selection independently of dae.
package xraycore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

type Selection struct {
	Mode    string `json:"mode"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
}
type state struct {
	Current  Selection  `json:"current"`
	Previous *Selection `json:"previous,omitempty"`
}
type Status struct {
	Mode        string
	Path        string
	Version     string
	Error       string
	CanRollback bool
}

type Manager struct {
	op        sync.Mutex
	mu        sync.RWMutex
	dir       string
	state     state
	validate  func(context.Context, string) error
	activated func()
	taskMu    sync.RWMutex
	task      Task
}

var Default = &Manager{}

func (m *Manager) SetHooks(validate func(context.Context, string) error, activated func()) {
	m.validate, m.activated = validate, activated
}

// Configure is called before the proxy and API start. A corrupt state must never
// silently switch a user's chosen core back to a different executable.
func (m *Manager) Configure(configDir string) error {
	m.dir = filepath.Join(configDir, "xray")
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		return err
	}
	defer m.restoreTask()
	b, err := os.ReadFile(filepath.Join(m.dir, "selection.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &m.state); err != nil {
		return fmt.Errorf("read Xray selection: %w", err)
	}
	_, err = m.resolve(m.state.Current)
	return err
}

func (m *Manager) resolve(s Selection) (string, error) {
	switch s.Mode {
	case "", "bundled":
		return exec.LookPath("xray")
	case "system":
		if s.Path == "" {
			return exec.LookPath("xray")
		}
		if !filepath.IsAbs(s.Path) {
			return "", errors.New("Xray path must be absolute")
		}
		return s.Path, nil
	case "managed":
		if !versionPattern.MatchString(s.Version) || m.dir == "" {
			return "", errors.New("invalid managed Xray version")
		}
		return filepath.Join(m.dir, s.Version, executableName()), nil
	default:
		return "", errors.New("unknown Xray mode")
	}
}

func (m *Manager) Binary() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.resolve(m.state.Current)
}

func probe(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return "", fmt.Errorf("cannot run Xray version: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 || fields[0] != "Xray" {
		return "", errors.New("selected executable is not Xray")
	}
	return fields[1], nil
}

func (m *Manager) Status(ctx context.Context) *Status {
	m.mu.RLock()
	s, previous := m.state.Current, m.state.Previous != nil
	path, err := m.resolve(s)
	m.mu.RUnlock()
	mode := s.Mode
	if mode == "" {
		mode = "bundled"
	}
	status := &Status{Mode: mode, Path: path, CanRollback: previous}
	if err == nil {
		status.Version, err = probe(ctx, path)
	}
	if err != nil {
		status.Error = err.Error()
	}
	return status
}

func (m *Manager) activate(ctx context.Context, s Selection) (*Status, error) {
	report(ctx, "validating", 0, 0)
	path, err := m.resolve(s)
	if err != nil {
		return nil, err
	}
	if _, err = probe(ctx, path); err != nil {
		return nil, err
	}
	if m.validate != nil {
		if err = m.validate(ctx, path); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report(ctx, "switching", 0, 0)
	m.mu.RLock()
	old := m.state.Current
	m.mu.RUnlock()
	next := state{Current: s, Previous: &old}
	if err := m.save(next); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.state = next
	m.mu.Unlock()
	if m.activated != nil {
		m.activated()
	}
	return m.Status(ctx), nil
}

func (m *Manager) save(s state) error {
	if m.dir == "" {
		return errors.New("Xray manager has not been configured")
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.dir, ".selection-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(m.dir, "selection.json"))
}

func (m *Manager) Select(ctx context.Context, mode, path string) (*Status, error) {
	m.op.Lock()
	defer m.op.Unlock()
	return m.selectCore(ctx, mode, path)
}

func (m *Manager) selectCore(ctx context.Context, mode, path string) (*Status, error) {
	if mode != "bundled" && mode != "system" {
		return nil, errors.New("select bundled or system mode")
	}
	if mode == "bundled" {
		path = ""
	}
	return m.activate(ctx, Selection{Mode: mode, Path: strings.TrimSpace(path)})
}

func (m *Manager) Rollback(ctx context.Context) (*Status, error) {
	m.op.Lock()
	defer m.op.Unlock()
	return m.rollback(ctx)
}

func (m *Manager) rollback(ctx context.Context) (*Status, error) {
	m.mu.RLock()
	previous := m.state.Previous
	m.mu.RUnlock()
	if previous == nil {
		return nil, errors.New("no previous Xray selection")
	}
	return m.activate(ctx, *previous)
}
