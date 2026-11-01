// SPDX-License-Identifier: AGPL-3.0-only
package xraycore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func awaitTask(t *testing.T, m *Manager) *Task {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		task := m.Task()
		if task.Status != "running" && m.op.TryLock() {
			m.op.Unlock()
			return task
		}
		select {
		case <-deadline:
			t.Fatal("background task did not complete")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestBackgroundTaskReturnsWithoutWaitingAndRejectsDuplicate(t *testing.T) {
	m := &Manager{}
	dir := t.TempDir()
	if err := m.Configure(dir); err != nil {
		t.Fatal(err)
	}
	path := fakeCore(t, t.TempDir(), "26.10.31")
	entered, release := make(chan struct{}), make(chan struct{})
	m.SetHooks(func(context.Context, string) error { close(entered); <-release; return nil }, nil)
	accepted, err := m.StartTask("system", "", path)
	if err != nil || accepted.Status != "running" || accepted.ID == "" {
		t.Fatalf("accept: %+v %v", accepted, err)
	}
	<-entered
	if task := m.Task(); task.Phase != "validating" {
		t.Fatal(task)
	}
	if _, err := m.StartTask("bundled", "", ""); err == nil {
		t.Fatal("accepted duplicate task")
	}
	close(release)
	if task := awaitTask(t, m); task.Status != "succeeded" {
		t.Fatal(task)
	}
	n := &Manager{}
	if err := n.Configure(dir); err != nil {
		t.Fatal(err)
	}
	if n.Task().ID != accepted.ID || n.Task().Status != "succeeded" {
		t.Fatal(n.Task())
	}
}

func TestBackgroundFailureRetainsCoreAndError(t *testing.T) {
	m := &Manager{}
	if err := m.Configure(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	path := fakeCore(t, t.TempDir(), "26.10.31")
	m.SetHooks(func(context.Context, string) error { return errors.New("configuration rejected") }, nil)
	if _, err := m.StartTask("system", "", path); err != nil {
		t.Fatal(err)
	}
	task := awaitTask(t, m)
	if task.Status != "failed" || task.Error != "validating: configuration rejected" {
		t.Fatal(task)
	}
	if m.state.Current.Mode != "" {
		t.Fatal("failed update changed selected core")
	}
}

func TestBackgroundDownloadSurvivesRequestEndAndReportsNetworkFailure(t *testing.T) {
	m := &Manager{}
	if err := m.Configure(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	name, err := assetName()
	if err != nil {
		t.Skip(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	old := downloadClient
	t.Cleanup(func() { downloadClient = old })
	downloadClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "api.github.com" {
			body, _ := json.Marshal(githubRelease{Tag: "v26.10.31", Assets: []asset{{Name: name, URL: "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/" + name, Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
		}
		close(entered)
		<-release
		if r.Context().Err() != nil {
			t.Error("task inherited canceled request")
		}
		return nil, errors.New("download connection timed out")
	})}
	// The API request ends immediately after StartTask; work has no request context.
	if _, err := m.StartTask("install", "v26.10.31", ""); err != nil {
		t.Fatal(err)
	}
	<-entered
	if task := m.Task(); task.Phase != "connecting" {
		t.Fatal(task)
	}
	close(release)
	task := awaitTask(t, m)
	if task.Status != "failed" || task.Error == "" {
		t.Fatal(task)
	}
	if m.state.Current.Mode != "" {
		t.Fatal("network failure changed selection")
	}
}

func TestProgressAndRestartRecovery(t *testing.T) {
	var got int32
	ctx := context.WithValue(context.Background(), progressKey{}, progressFunc(func(phase string, downloaded, total int32) {
		if phase != "downloading" || total != 6 {
			t.Fatal(phase, total)
		}
		got = downloaded
	}))
	r := &progressReader{ctx: ctx, reader: bytes.NewBufferString("abcdef"), total: 6}
	if _, err := io.ReadAll(r); err != nil || got != 6 {
		t.Fatal(err, got)
	}
	dir := t.TempDir()
	m := &Manager{}
	if err := m.Configure(dir); err != nil {
		t.Fatal(err)
	}
	if err := m.persistTask(Task{ID: "interrupted", Status: "running", Phase: "downloading"}); err != nil {
		t.Fatal(err)
	}
	n := &Manager{}
	if err := n.Configure(dir); err != nil {
		t.Fatal(err)
	}
	if n.Task().Status != "failed" || n.Task().Error == "" {
		t.Fatal(n.Task())
	}
	if _, err := os.Stat(filepath.Join(m.dir, "update-task.json")); err != nil {
		t.Fatal(err)
	}
}
