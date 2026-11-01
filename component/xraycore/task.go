// SPDX-License-Identifier: AGPL-3.0-only
package xraycore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Task struct {
	ID              string
	Status          string
	Kind            string
	Version         string
	Phase           string
	DownloadedBytes int32
	TotalBytes      int32
	Error           string
	Attempt         int32
	MaxAttempts     int32
	LastError       string
}

type attemptKey struct{}
type attemptFunc func(int32, int32, string)

func reportAttempt(ctx context.Context, attempt, max int32, lastError string) {
	if notify, ok := ctx.Value(attemptKey{}).(attemptFunc); ok {
		notify(attempt, max, lastError)
	}
}

type progressKey struct{}
type progressFunc func(string, int32, int32)

func report(ctx context.Context, phase string, downloaded, total int32) {
	if notify, ok := ctx.Value(progressKey{}).(progressFunc); ok {
		notify(phase, downloaded, total)
	}
}

type progressReader struct {
	ctx        context.Context
	reader     io.Reader
	downloaded int64
	total      int64
}

func (r *progressReader) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	r.downloaded += int64(n)
	total := r.total
	if total < 0 || total > 96<<20 {
		total = 0
	}
	report(r.ctx, "downloading", int32(r.downloaded), int32(total))
	return n, err
}

func (m *Manager) Task() *Task {
	m.taskMu.RLock()
	defer m.taskMu.RUnlock()
	t := m.task
	if t.Status == "" {
		t.Status = "idle"
	}
	return &t
}

// StartTask reserves the operation lock before returning. Work has its own
// bounded lifetime, so a reverse-proxy timeout or closed browser cannot cancel it.
func (m *Manager) StartTask(kind, version, path string) (*Task, error) {
	if m.dir == "" {
		return nil, errors.New("Xray manager has not been configured")
	}
	if kind != "install" && kind != "system" && kind != "bundled" && kind != "rollback" {
		return nil, errors.New("invalid Xray task kind")
	}
	if kind == "install" && !versionPattern.MatchString(version) {
		return nil, errors.New("invalid Xray release version")
	}
	if !m.op.TryLock() {
		return nil, errors.New("an Xray operation is already running; check its progress")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		m.op.Unlock()
		return nil, err
	}
	t := Task{ID: hex.EncodeToString(id[:]), Status: "running", Kind: kind, Version: version, Phase: "queued"}
	if err := m.persistTask(t); err != nil {
		m.op.Unlock()
		return nil, err
	}
	m.taskMu.Lock()
	m.task = t
	m.taskMu.Unlock()
	go func() {
		defer m.op.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		ctx = context.WithValue(ctx, progressKey{}, progressFunc(func(phase string, downloaded, total int32) {
			m.taskMu.Lock()
			m.task.Phase = phase
			if phase == "downloading" {
				m.task.DownloadedBytes, m.task.TotalBytes = downloaded, total
			}
			m.taskMu.Unlock()
		}))
		ctx = context.WithValue(ctx, attemptKey{}, attemptFunc(func(attempt, max int32, lastError string) {
			m.taskMu.Lock()
			m.task.Attempt, m.task.MaxAttempts, m.task.LastError = attempt, max, lastError
			m.task.DownloadedBytes, m.task.TotalBytes = 0, 0
			m.taskMu.Unlock()
		}))
		var err error
		switch kind {
		case "install":
			_, err = m.install(ctx, version)
		case "rollback":
			_, err = m.rollback(ctx)
		default:
			_, err = m.selectCore(ctx, kind, path)
		}
		m.taskMu.Lock()
		if err != nil {
			m.task.Status = "failed"
			m.task.Error = fmt.Sprintf("%s: %v", m.task.Phase, err)
		} else {
			m.task.Status, m.task.Phase = "succeeded", "done"
			m.task.LastError = ""
		}
		finished := m.task
		m.taskMu.Unlock()
		if err := m.persistTask(finished); err != nil {
			m.taskMu.Lock()
			m.task.Error = fmt.Sprintf("%s; save task result: %v", m.task.Error, err)
			m.taskMu.Unlock()
		}
	}()
	// Return the accepted snapshot, not a racing completion result.
	return &t, nil
}

func (m *Manager) persistTask(task Task) error {
	b, err := json.Marshal(task)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.dir, ".task-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(m.dir, "update-task.json"))
}

func (m *Manager) restoreTask() {
	b, err := os.ReadFile(filepath.Join(m.dir, "update-task.json"))
	if err != nil {
		return
	}
	if json.Unmarshal(b, &m.task) != nil {
		m.task = Task{}
		return
	}
	if m.task.Status == "running" {
		m.task.Status = "failed"
		m.task.Error = "daed restarted before the task finished; check the selected core and retry"
		_ = m.persistTask(m.task)
	}
}
