// SPDX-License-Identifier: AGPL-3.0-only
package xraycore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type cutReader struct{}

func (*cutReader) Read(b []byte) (int, error) { return copy(b, "partial"), io.ErrUnexpectedEOF }
func (*cutReader) Close() error               { return nil }

func TestDownloadRecoversFromUnexpectedEOF(t *testing.T) {
	old, oldHTTP1 := downloadClient, downloadHTTP1Client
	t.Cleanup(func() { downloadClient, downloadHTTP1Client = old, oldHTTP1 })
	calls := 0
	downloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, io.ErrUnexpectedEOF
		}
		if calls == 2 {
			return &http.Response{StatusCode: 200, Body: &cutReader{}, Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString("complete")), ContentLength: 8, Header: make(http.Header)}, nil
	})}
	downloadHTTP1Client = downloadClient
	var phases []string
	var attempt int32
	ctx := context.WithValue(context.Background(), progressKey{}, progressFunc(func(phase string, downloaded, total int32) { phases = append(phases, phase) }))
	ctx = context.WithValue(ctx, attemptKey{}, attemptFunc(func(n, max int32, last string) {
		attempt = n
		if max != 3 {
			t.Fatal(max)
		}
	}))
	b, err := getDownload(ctx, "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/test.zip", 100, true)
	if err != nil || string(b) != "complete" || calls != 3 || attempt != 3 {
		t.Fatal(string(b), err, calls, attempt)
	}
	var unique []string
	for _, phase := range phases {
		if len(unique) == 0 || unique[len(unique)-1] != phase {
			unique = append(unique, phase)
		}
	}
	if strings.Join(unique, ",") != "connecting,retrying,connecting,downloading,retrying,connecting,downloading" {
		t.Fatal(phases)
	}
}

func TestDownloadRetriesAreBoundedAndCancelDuringBackoff(t *testing.T) {
	old, oldHTTP1 := downloadClient, downloadHTTP1Client
	t.Cleanup(func() { downloadClient, downloadHTTP1Client = old, oldHTTP1 })
	calls := 0
	downloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, io.ErrUnexpectedEOF })}
	downloadHTTP1Client = downloadClient
	_, err := getDownload(context.Background(), "https://github.com/test", 100, true)
	if err == nil || calls != 3 || !strings.Contains(err.Error(), "3 attempt") {
		t.Fatal(calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, progressKey{}, progressFunc(func(phase string, _, _ int32) {
		if phase == "retrying" {
			cancel()
		}
	}))
	calls = 0
	start := time.Now()
	_, err = getDownload(ctx, "https://github.com/test", 100, true)
	if !errors.Is(err, context.Canceled) || calls != 1 || time.Since(start) > time.Second {
		t.Fatal(calls, err)
	}
}

func TestPermanentDownloadFailuresAreNotRetried(t *testing.T) {
	old, oldHTTP1 := downloadClient, downloadHTTP1Client
	t.Cleanup(func() { downloadClient, downloadHTTP1Client = old, oldHTTP1 })
	for _, code := range []int{403, 404} {
		calls := 0
		downloadClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})}
		downloadHTTP1Client = downloadClient
		_, err := getDownload(context.Background(), "https://github.com/test", 100, true)
		if err == nil || calls != 1 {
			t.Fatal(code, calls, err)
		}
	}
	if retryableDownload(errors.New("Xray archive SHA256 mismatch")) {
		t.Fatal("retrying validation failure")
	}
}

func TestRetryClientUsesVerifiedHTTP1(t *testing.T) {
	versions := make(chan int, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { versions <- r.ProtoMajor; w.Write([]byte("ok")) }))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := newDownloadClient(true)
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	defer transport.CloseIdleConnections()
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if version := <-versions; version != 1 {
		t.Fatal("fallback did not negotiate HTTP/1.1", version)
	}
	// An untrusted certificate must still be rejected by the production client.
	untrusted := newDownloadClient(true)
	defer untrusted.Transport.(*http.Transport).CloseIdleConnections()
	if response, err = untrusted.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("fallback disabled certificate verification")
	}
}

func TestOfficialAssetAPIFallsBackWithoutCombiningPartialData(t *testing.T) {
	old, oldHTTP1 := downloadClient, downloadHTTP1Client
	t.Cleanup(func() { downloadClient, downloadHTTP1Client = old, oldHTTP1 })
	api := "https://api.github.com/repos/XTLS/Xray-core/releases/assets/123"
	browser := "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/test.zip"
	var sources []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sources = append(sources, r.URL.String())
		if len(sources) == 1 {
			if r.Header.Get("Accept") != "application/octet-stream" {
				t.Error("asset API did not request binary content")
			}
			return nil, io.ErrUnexpectedEOF
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("whole archive")), Header: make(http.Header)}, nil
	})}
	downloadClient, downloadHTTP1Client = client, client
	b, err := getArchive(context.Background(), api, browser, 100)
	if err != nil || string(b) != "whole archive" || len(sources) != 2 || sources[0] != api || sources[1] != browser {
		t.Fatal(sources, string(b), err)
	}
}
