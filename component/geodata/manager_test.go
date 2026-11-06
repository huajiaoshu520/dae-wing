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
	if err := download(context.Background(), path, asset, &data.GeoSiteList{}); err != nil {
		t.Fatal(err)
	}
	body[10] ^= 1
	if err := download(context.Background(), path, asset, &data.GeoSiteList{}); err == nil {
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
