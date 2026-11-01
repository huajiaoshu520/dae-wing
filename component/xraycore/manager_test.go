// SPDX-License-Identifier: AGPL-3.0-only
package xraycore

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fakeCore(t *testing.T, dir, version string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	path := filepath.Join(dir, "xray")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'Xray "+version+" (Xray, Penetrates Everything.)'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSelectionPersistsAndRollsBack(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	base := fakeCore(t, t.TempDir(), "26.10.29")
	t.Setenv("PATH", filepath.Dir(base))
	custom := fakeCore(t, t.TempDir(), "26.10.31")
	m := &Manager{}
	if err := m.Configure(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Select(ctx, "system", custom); err != nil {
		t.Fatal(err)
	}
	restarted := &Manager{}
	if err := restarted.Configure(dir); err != nil {
		t.Fatal(err)
	}
	if s := restarted.Status(ctx); s.Version != "26.10.31" || !s.CanRollback {
		t.Fatalf("bad persistent status: %+v", s)
	}
	if s, err := restarted.Rollback(ctx); err != nil || s.Version != "26.10.29" {
		t.Fatalf("rollback: %+v %v", s, err)
	}
}

func TestFailedValidationKeepsStateAndWorkers(t *testing.T) {
	ctx := context.Background()
	m := &Manager{}
	if err := m.Configure(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	custom := fakeCore(t, t.TempDir(), "26.10.31")
	called := false
	m.SetHooks(func(context.Context, string) error { return errors.New("incompatible") }, func() { called = true })
	if _, err := m.Select(ctx, "system", custom); err == nil {
		t.Fatal("accepted incompatible core")
	}
	if called || m.state.Current.Mode != "" {
		t.Fatal("failed validation changed current core")
	}
	if _, err := os.Stat(filepath.Join(m.dir, "selection.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed validation wrote selection")
	}
	if _, err := m.Select(ctx, "system", "relative/xray"); err == nil {
		t.Fatal("accepted relative path")
	}
	if _, err := m.Install(ctx, "../../outside"); err == nil {
		t.Fatal("accepted unsafe version")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInstallChecksDigestAndPreservesSelection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	name, err := assetName()
	if err != nil {
		t.Skip(err)
	}
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	f, _ := w.Create(executableName())
	f.Write([]byte("#!/bin/sh\necho 'Xray 26.10.31 (Xray, Penetrates Everything.)'\n"))
	// A malicious path must never be extracted.
	f, _ = w.Create("../escaped")
	f.Write([]byte("escape"))
	w.Close()
	digest := sha256.Sum256(archive.Bytes())
	a := asset{Name: name, URL: "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/" + name, Digest: "sha256:" + hex.EncodeToString(digest[:])}
	bad := true
	previous := downloadClient
	t.Cleanup(func() { downloadClient = previous })
	downloadClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var b []byte
		if r.URL.Host == "api.github.com" {
			b, _ = json.Marshal(githubRelease{Tag: "v26.10.31", Assets: []asset{a}})
		} else {
			b = archive.Bytes()
			if bad {
				b = []byte("tampered download")
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
	})}
	m := &Manager{}
	if err := m.Configure(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Install(context.Background(), "v26.10.31"); err == nil || !strings.Contains(err.Error(), "SHA256 mismatch") {
		t.Fatalf("tampered core: %v", err)
	}
	if m.state.Current.Mode != "" {
		t.Fatal("tampered install changed core")
	}
	bad = false
	s, err := m.Install(context.Background(), "v26.10.31")
	if err != nil || s.Mode != "managed" || s.Version != "26.10.31" {
		t.Fatalf("install: %+v %v", s, err)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "escaped")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("archive path escaped")
	}
	if _, err := m.Install(context.Background(), "v26.10.31"); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
}
