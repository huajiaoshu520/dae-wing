// SPDX-License-Identifier: AGPL-3.0-only
package xraycore

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type Release struct {
	Version    string
	Prerelease bool
}
type asset struct {
	ID     int64  `json:"id"`
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

var downloadClient = newDownloadClient(false)
var downloadHTTP1Client = newDownloadClient(true)

func newDownloadClient(http1 bool) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	t.TLSHandshakeTimeout = 10 * time.Second
	t.ResponseHeaderTimeout = 20 * time.Second
	if http1 {
		t.ForceAttemptHTTP2 = false
		t.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	}
	return &http.Client{Transport: t, Timeout: 3 * time.Minute}
}

const downloadAttempts = 3

var errDownloadIdle = errors.New("Xray download received no data for 30 seconds")
var errAssetMetadata = errors.New("GitHub asset API returned metadata instead of archive bytes")

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("GitHub returned HTTP %d; check connectivity or rate limits", e.code)
}

func retryableDownload(err error) bool {
	var status *httpStatusError
	if errors.As(err, &status) {
		return status.code == 408 || status.code == 429 || status.code >= 500
	}
	var network net.Error
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, errDownloadIdle) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		(errors.As(err, &network) && (network.Timeout() || network.Temporary()))
}

type idleReader struct {
	reader io.Reader
	timer  *time.Timer
}

func (r *idleReader) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	if n > 0 {
		r.timer.Reset(30 * time.Second)
	}
	return n, err
}

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
	return getDownload(ctx, address, limit, false)
}

func getDownload(ctx context.Context, address string, limit int64, progress bool) ([]byte, error) {
	if !progress {
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		return getDownloadOnce(ctx, address, limit, false, downloadClient)
	}
	return getArchive(ctx, address, "", limit)
}

func getArchive(ctx context.Context, address, alternate string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var last error
	used := 0
	for attempt := 1; attempt <= downloadAttempts; attempt++ {
		used = attempt
		detail := ""
		if last != nil {
			detail = last.Error()
		}
		reportAttempt(ctx, int32(attempt), downloadAttempts, detail)
		client := downloadClient
		if attempt > 1 {
			client = downloadHTTP1Client
		}
		source := address
		if attempt == 2 && alternate != "" {
			source = alternate
		}
		b, err := getDownloadOnce(ctx, source, limit, true, client)
		if err == nil {
			return b, nil
		}
		last = err
		if ctx.Err() != nil || (!retryableDownload(err) && !(alternate != "" && errors.Is(err, errAssetMetadata))) {
			break
		}
		if attempt < downloadAttempts {
			reportAttempt(ctx, int32(attempt), downloadAttempts, err.Error())
			report(ctx, "retrying", 0, 0)
			timer := time.NewTimer(time.Duration(attempt) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return nil, fmt.Errorf("Xray archive download failed after %d attempt(s): %w", used, last)
}

func getDownloadOnce(ctx context.Context, address string, limit int64, progress bool, client *http.Client) ([]byte, error) {
	var idleTimer *time.Timer
	if progress {
		report(ctx, "connecting", 0, 0)
		var cancel context.CancelCauseFunc
		ctx, cancel = context.WithCancelCause(ctx)
		idleTimer = time.AfterFunc(30*time.Second, func() { cancel(errDownloadIdle) })
		defer idleTimer.Stop()
		defer cancel(nil)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "daed-xray-manager")
	if progress && strings.HasPrefix(address, "https://api.github.com/repos/XTLS/Xray-core/releases/assets/") {
		req.Header.Set("Accept", "application/octet-stream")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(context.Cause(ctx), errDownloadIdle) {
			return nil, errDownloadIdle
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{code: resp.StatusCode}
	}
	if progress && strings.Contains(resp.Header.Get("Content-Type"), "json") {
		return nil, errAssetMetadata
	}
	var reader io.Reader = resp.Body
	if progress {
		total := resp.ContentLength
		if total < 0 || total > limit {
			total = 0
		}
		report(ctx, "downloading", 0, int32(total))
		reader = &progressReader{ctx: ctx, reader: &idleReader{reader: resp.Body, timer: idleTimer}, total: resp.ContentLength}
	}
	b, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil && errors.Is(context.Cause(ctx), errDownloadIdle) {
		return nil, errDownloadIdle
	}
	if err == nil && int64(len(b)) > limit {
		return nil, errors.New("Xray download exceeds size limit")
	}
	return b, err
}

func (m *Manager) Releases(ctx context.Context) ([]*Release, error) {
	b, err := get(ctx, "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=30", 8<<20)
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
	return m.install(ctx, version)
}

func (m *Manager) install(ctx context.Context, version string) (*Status, error) {
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
	report(ctx, "metadata", 0, 0)
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
	primary, alternate := selected.URL, ""
	if selected.ID > 0 {
		primary = fmt.Sprintf("https://api.github.com/repos/XTLS/Xray-core/releases/assets/%d", selected.ID)
		alternate = selected.URL
	}
	archive, err := getArchive(ctx, primary, alternate, 96<<20)
	if err != nil {
		return nil, err
	}
	report(ctx, "verifying", 0, 0)
	sum := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return nil, errors.New("Xray archive SHA256 mismatch; current core was kept")
	}
	report(ctx, "extracting", 0, 0)
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
