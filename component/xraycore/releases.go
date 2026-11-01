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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Release struct {
	Version    string
	Prerelease bool
}
type asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
}
type githubRelease struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []asset `json:"assets"`
}

var downloadClient = &http.Client{Timeout: 3 * time.Minute}

func executableName() string {
	if runtime.GOOS == "windows" {
		return "xray.exe"
	}
	return "xray"
}

func assetName() (string, error) {
	arch := map[string]string{"amd64": "64", "arm64": "arm64-v8a", "386": "32"}[runtime.GOARCH]
	// arm binaries differ by CPU capability. Do not guess on a 32-bit ARM host.
	if arch == "" {
		return "", fmt.Errorf("automatic Xray download is unsupported for %s; use a custom path", runtime.GOARCH)
	}
	osName := map[string]string{"linux": "linux", "darwin": "macos", "windows": "windows"}[runtime.GOOS]
	if osName == "" {
		return "", errors.New("unsupported Xray operating system")
	}
	return "Xray-" + osName + "-" + arch + ".zip", nil
}

func get(ctx context.Context, address string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "daed-xray-manager")
	resp, err := downloadClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned HTTP %d; check connectivity or rate limits", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(b)) > limit {
		return nil, errors.New("Xray download exceeds size limit")
	}
	return b, err
}

func (m *Manager) Releases(ctx context.Context) ([]*Release, error) {
	b, err := get(ctx, "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=30", 4<<20)
	if err != nil {
		return nil, err
	}
	var releases []githubRelease
	if err = json.Unmarshal(b, &releases); err != nil {
		return nil, err
	}
	name, err := assetName()
	if err != nil {
		return nil, err
	}
	result := make([]*Release, 0)
	for _, r := range releases {
		if r.Draft || !versionPattern.MatchString(r.Tag) {
			continue
		}
		for _, a := range r.Assets {
			if a.Name == name && strings.HasPrefix(a.Digest, "sha256:") {
				result = append(result, &Release{Version: r.Tag, Prerelease: r.Prerelease})
				break
			}
		}
	}
	return result, nil
}

func (m *Manager) Install(ctx context.Context, version string) (*Status, error) {
	m.op.Lock()
	defer m.op.Unlock()
	if m.dir == "" {
		return nil, errors.New("Xray manager has not been configured")
	}
	if !versionPattern.MatchString(version) {
		return nil, errors.New("invalid Xray release version")
	}
	name, err := assetName()
	if err != nil {
		return nil, err
	}
	b, err := get(ctx, "https://api.github.com/repos/XTLS/Xray-core/releases/tags/"+version, 1<<20)
	if err != nil {
		return nil, err
	}
	var release githubRelease
	if err = json.Unmarshal(b, &release); err != nil {
		return nil, err
	}
	if release.Draft || release.Tag != version {
		return nil, errors.New("invalid official Xray release")
	}
	var selected *asset
	for i := range release.Assets {
		if release.Assets[i].Name == name {
			selected = &release.Assets[i]
			break
		}
	}
	if selected == nil {
		return nil, errors.New("release has no binary for this platform")
	}
	u, err := url.Parse(selected.URL)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || !strings.HasPrefix(u.Path, "/XTLS/Xray-core/releases/download/"+version+"/") {
		return nil, errors.New("unexpected Xray download source")
	}
	want := strings.TrimPrefix(selected.Digest, "sha256:")
	if !strings.HasPrefix(selected.Digest, "sha256:") || len(want) != 64 {
		return nil, errors.New("official release is missing its SHA256 digest")
	}
	archive, err := get(ctx, selected.URL, 96<<20)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return nil, errors.New("Xray archive SHA256 mismatch; current core was kept")
	}
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	var binary *zip.File
	for _, f := range z.File {
		if f.Name == executableName() {
			binary = f
			break
		}
	}
	if binary == nil || binary.UncompressedSize64 > 160<<20 {
		return nil, errors.New("invalid Xray archive executable")
	}
	folder := filepath.Join(m.dir, version)
	if err = os.MkdirAll(folder, 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(folder, ".download-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	r, err := binary.Open()
	if err != nil {
		f.Close()
		return nil, err
	}
	_, copyErr := io.Copy(f, io.LimitReader(r, (160<<20)+1))
	r.Close()
	closeErr := f.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err = os.Chmod(f.Name(), 0700); err != nil {
		return nil, err
	}
	actual, err := probe(ctx, f.Name())
	if err != nil {
		return nil, err
	}
	if "v"+actual != version {
		return nil, errors.New("downloaded Xray version does not match release")
	}
	// Never replace a running executable. Reuse an identical installed version.
	target := filepath.Join(folder, executableName())
	old, readErr := os.ReadFile(target)
	if readErr == nil {
		candidate, err := os.ReadFile(f.Name())
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(old, candidate) {
			return nil, errors.New("installed release differs; select another version first")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	} else if err = os.Rename(f.Name(), target); err != nil {
		return nil, err
	}
	return m.activate(ctx, Selection{Mode: "managed", Version: version})
}
