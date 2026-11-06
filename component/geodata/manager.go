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
	restart     func() error
}

type File struct {
	Name, Path, Updated string
}

type Status struct {
	Daily, Running bool
	Error          string
	UpdateTime     string
	Files          []*File
}

func (m *Manager) Configure(ctx context.Context, configDir string, restart func() error) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restart = restart
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
			now := time.Now().In(updateZone)
			daily, at := m.daily()
			checked, _ := os.ReadFile(filepath.Join(m.root, "last-check"))
			if daily && now.Format("15:04") >= at && string(checked) != now.Format(time.DateOnly) && !m.running && !now.Before(m.nextAttempt) {
				m.start(ctx, now.Format(time.DateOnly))
			}
			m.mu.Unlock()
		}
	}
}

const defaultUpdateTime = "04:17"

var updateZone = time.FixedZone("UTC+8", 8*60*60)

func (m *Manager) daily() (bool, string) {
	if m.root == "" {
		return false, defaultUpdateTime
	}
	value, err := os.ReadFile(filepath.Join(m.root, "daily"))
	if len(value) == 0 {
		return err == nil, defaultUpdateTime
	}
	at, disabled := strings.CutPrefix(string(value), "off:")
	return err == nil && !disabled, at
}

func (m *Manager) Status() *Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	daily, at := m.daily()
	status := &Status{Daily: daily, UpdateTime: at, Running: m.running, Error: m.lastError, Files: []*File{}}
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

func (m *Manager) SetDaily(enabled bool, at string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.root == "" {
		return fmt.Errorf("geodata manager is unavailable")
	}
	path := filepath.Join(m.root, "daily")
	if err := os.MkdirAll(m.root, 0700); err != nil {
		return err
	}
	if at == "" {
		_, at = m.daily()
	}
	parsed, err := time.Parse("15:04", at)
	if err != nil || parsed.Format("15:04") != at {
		return fmt.Errorf("expected update time in HH:MM format")
	}
	if !enabled {
		at = "off:" + at
	}
	return os.WriteFile(path, []byte(at), 0600)
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.root == "" || m.running {
		return fmt.Errorf("geodata manager is unavailable or updating")
	}
	m.start(context.Background(), "")
	return nil
}

func (m *Manager) start(parent context.Context, date string) {
	m.running = true
	m.lastError = ""
	m.nextAttempt = time.Now().Add(time.Hour)
	go func() {
		ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
		defer cancel()
		changed, err := m.update(ctx)
		if err == nil && date != "" {
			err = os.WriteFile(filepath.Join(m.root, "last-check"), []byte(date), 0600)
		}
		if changed && m.restart != nil {
			if restartErr := m.restart(); restartErr != nil && err == nil {
				err = restartErr
			}
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		m.running = false
		if err != nil {
			m.lastError = err.Error()
			logrus.WithError(err).Warn("Geodata update failed")
		}
	}()
}

func (m *Manager) update(ctx context.Context) (bool, error) {
	if err := os.MkdirAll(m.root, 0700); err != nil {
		return false, err
	}
	release, err := latestRelease(ctx)
	if err != nil {
		return false, err
	}
	finder := assets.NewLocationFinder(m.dirs)
	unchanged := true
	for name, asset := range release {
		path, err := finder.GetLocationAsset(logrus.StandardLogger(), name)
		if err != nil {
			unchanged = false
			break
		}
		file, err := os.Open(path)
		if err != nil {
			unchanged = false
			break
		}
		hash := sha256.New()
		_, err = io.Copy(hash, io.LimitReader(file, (64<<20)+1))
		_ = file.Close()
		if err != nil || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != asset.Digest {
			unchanged = false
			break
		}
	}
	if unchanged {
		return false, nil
	}
	dir, err := os.MkdirTemp(m.root, "release-")
	if err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(dir)
		}
	}()
	for _, file := range []struct {
		name    string
		message proto.Message
	}{
		{"geoip.dat", &data.GeoIPList{}}, {"geosite.dat", &data.GeoSiteList{}},
	} {
		if err := download(ctx, filepath.Join(dir, file.name), release[file.name], file.message); err != nil {
			return false, fmt.Errorf("%s: %w", file.name, err)
		}
	}
	current := filepath.Join(m.root, "current")
	previous, _ := os.Readlink(current)
	link := filepath.Join(dir, ".activate")
	if err := os.Symlink(filepath.Base(dir), link); err != nil {
		return false, err
	}
	if err := os.Rename(link, current); err != nil {
		return false, err
	}
	committed = true
	entries, err := os.ReadDir(m.root)
	if err != nil {
		return true, nil
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() && strings.HasPrefix(name, "release-") && name != previous && name != filepath.Base(dir) {
			if err := os.RemoveAll(filepath.Join(m.root, name)); err != nil {
				logrus.WithError(err).Warn("Failed to clean old geodata")
			}
		}
	}
	return true, nil
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
