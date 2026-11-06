// SPDX-License-Identifier: AGPL-3.0-only
package geodata

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	data "github.com/daeuniverse/dae/pkg/geodata"
	"google.golang.org/protobuf/proto"
)

func TestDownloadRejectsCorruptRules(t *testing.T) {
	body, err := proto.Marshal(&data.GeoSiteList{Entry: []*data.GeoSite{{CountryCode: strings.Repeat("a", 2048)}}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "geosite.dat")
	asset := releaseAsset{URL: server.URL, Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(body))}
	if err := downloadRule(context.Background(), path, asset, &data.GeoSiteList{}, ruleSource{url: server.URL, timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	body[10] ^= 1
	if err := downloadRule(context.Background(), path, asset, &data.GeoSiteList{}, ruleSource{url: server.URL, timeout: time.Second}); err == nil {
		t.Fatal("corrupt data accepted")
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("sha256:%x", sha256.Sum256(saved)) != asset.Digest {
		t.Fatal("valid file replaced")
	}
}

func TestSchedulePersistsTimeAcrossToggle(t *testing.T) {
	m := Manager{root: t.TempDir()}
	if err := os.WriteFile(filepath.Join(m.root, "daily"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if enabled, at := m.daily(); !enabled || at != "04:17" {
		t.Fatalf("legacy schedule: %v %s", enabled, at)
	}
	if err := m.SetDaily(true, "05:30"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetDaily(false, ""); err != nil {
		t.Fatal(err)
	}
	if enabled, at := m.daily(); enabled || at != "05:30" {
		t.Fatalf("disabled schedule: %v %s", enabled, at)
	}
	if err := m.SetDaily(true, "25:30"); err == nil {
		t.Fatal("invalid time accepted")
	}
	if err := m.SetDaily(true, ""); err != nil {
		t.Fatal(err)
	}
	if enabled, at := m.daily(); !enabled || at != "05:30" {
		t.Fatalf("re-enabled schedule: %v %s", enabled, at)
	}
}

func TestFetchRuleFallsBackToUpstreamReleaseBranch(t *testing.T) {
	valid := strings.Repeat("rule bytes", 128)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/partial" {
			w.Header().Set("Content-Length", "2000")
			_, _ = w.Write([]byte(valid))
			return
		}
		if r.URL.Path == "/api" {
			if r.Header.Get("Accept") != "application/octet-stream" {
				t.Error("missing binary Accept header")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
			return
		}
		if r.URL.Path == "/browser" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(valid))
	}))
	defer server.Close()
	body, err := fetchRule(context.Background(), fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(valid))), 4096,
		ruleSource{url: server.URL + "/partial", timeout: time.Second},
		ruleSource{url: server.URL + "/api", api: true, timeout: time.Second},
		ruleSource{url: server.URL + "/browser", timeout: time.Second},
		ruleSource{url: server.URL + "/raw", timeout: time.Second})
	if err != nil || string(body) != valid {
		t.Fatalf("fallback: %q, %v", body, err)
	}
}
