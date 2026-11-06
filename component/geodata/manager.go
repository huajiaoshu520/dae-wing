// SPDX-License-Identifier: AGPL-3.0-only
package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/assets"
	data "github.com/daeuniverse/dae/pkg/geodata"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

var Default Manager

type Manager struct {
	mu          sync.Mutex
	root        string
	dirs        []string
	running     bool
	lastError   string
	nextAttempt time.Time
}

type File struct {
	Name, Path, Updated string
}

type Status struct {
	Daily, Running bool
	Error          string
	Files          []*File
}

func (m *Manager) Configure(ctx context.Context, configDir string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.root = filepath.Join(configDir, "geodata")
	m.dirs = []string{filepath.Join(m.root, "current"), configDir}
	go m.schedule(ctx)
	return m.dirs
}

func (m *Manager) schedule(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			info, err := os.Stat(filepath.Join(m.root, "current"))
			due := err != nil || time.Since(info.ModTime()) >= 24*time.Hour
			if m.daily() && due && !m.running && !time.Now().Before(m.nextAttempt) {
				m.start(ctx)
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) daily() bool {
	if m.root == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(m.root, "daily"))
	return err == nil
}

func (m *Manager) Status() *Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := &Status{Daily: m.daily(), Running: m.running, Error: m.lastError, Files: []*File{}}
	finder := assets.NewLocationFinder(m.dirs)
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		file := &File{Name: name}
		if path, err := finder.GetLocationAsset(logrus.StandardLogger(), name); err == nil {
			if info, err := os.Stat(path); err == nil {
				file.Path = path
				file.Updated = info.ModTime().UTC().Format(time.RFC3339)
			}
		}
		status.Files = append(status.Files, file)
	}
	return status
}

func (m *Manager) SetDaily(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.root == "" {
		return fmt.Errorf("geodata manager is unavailable")
	}
	path := filepath.Join(m.root, "daily")
	if !enabled {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(m.root, 0700); err != nil {
		return err
	}
	return os.WriteFile(path, nil, 0600)
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.root == "" || m.running {
		return fmt.Errorf("geodata manager is unavailable or updating")
	}
	m.start(context.Background())
	return nil
}

func (m *Manager) start(parent context.Context) {
	m.running = true
	m.lastError = ""
	m.nextAttempt = time.Now().Add(time.Hour)
	go func() {
		ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
		defer cancel()
		err := m.update(ctx)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.running = false
		if err != nil {
			m.lastError = err.Error()
			logrus.WithError(err).Warn("Geodata update failed")
		}
	}()
}

func (m *Manager) update(ctx context.Context) error {
	if err := os.MkdirAll(m.root, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(m.root, "release-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(dir)
		}
	}()
	release, err := latestRelease(ctx)
	if err != nil {
		return err
	}
	for _, file := range []struct {
		name    string
		message proto.Message
	}{
		{"geoip.dat", &data.GeoIPList{}}, {"geosite.dat", &data.GeoSiteList{}},
	} {
		if err := download(ctx, filepath.Join(dir, file.name), release[file.name], file.message); err != nil {
			return fmt.Errorf("%s: %w", file.name, err)
		}
	}
	current := filepath.Join(m.root, "current")
	previous, _ := os.Readlink(current)
	link := filepath.Join(dir, ".activate")
	if err := os.Symlink(filepath.Base(dir), link); err != nil {
		return err
	}
	if err := os.Rename(link, current); err != nil {
		return err
	}
	committed = true
	entries, err := os.ReadDir(m.root)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() && strings.HasPrefix(name, "release-") && name != previous && name != filepath.Base(dir) {
			if err := os.RemoveAll(filepath.Join(m.root, name)); err != nil {
				logrus.WithError(err).Warn("Failed to clean old geodata")
			}
		}
	}
	return nil
}

type releaseAsset struct {
	Name   string
	URL    string `json:"browser_download_url"`
	Digest string
}

func latestRelease(ctx context.Context) (map[string]releaseAsset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release metadata: HTTP %s", response.Status)
	}
	var release struct{ Assets []releaseAsset }
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&release); err != nil {
		return nil, err
	}
	files := make(map[string]releaseAsset, 2)
	for _, asset := range release.Assets {
		if asset.Name != "geoip.dat" && asset.Name != "geosite.dat" {
			continue
		}
		if !strings.HasPrefix(asset.URL, "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/") ||
			!strings.HasSuffix(asset.URL, "/"+asset.Name) || !strings.HasPrefix(asset.Digest, "sha256:") || len(asset.Digest) != 71 {
			return nil, fmt.Errorf("invalid release metadata for %s", asset.Name)
		}
		files[asset.Name] = asset
	}
	if len(files) != 2 {
		return nil, fmt.Errorf("release is missing GeoIP or GeoSite")
	}
	return files, nil
}

func download(ctx context.Context, path string, asset releaseAsset, message proto.Message) error {
	const limit = 64 << 20
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return err
	}
	if len(body) < 1024 || len(body) > limit {
		return fmt.Errorf("unexpected file size: %d", len(body))
	}
	if fmt.Sprintf("sha256:%x", sha256.Sum256(body)) != asset.Digest {
		return fmt.Errorf("SHA-256 mismatch")
	}
	if err := proto.Unmarshal(body, message); err != nil {
		return err
	}
	fields := message.ProtoReflect()
	if fields.Get(fields.Descriptor().Fields().ByNumber(1)).List().Len() == 0 {
		return fmt.Errorf("empty rule list")
	}
	return os.WriteFile(path, body, 0600)
}
