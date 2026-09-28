package xray

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
)

const testID = "f7c43346-b688-4300-aa3b-350e6c94cfa7"

func testLink() string {
	return "vless://" + testID + "@127.0.0.1:443?type=xhttp&security=reality&pbk=" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + "&sni=localhost#test"
}

func TestConfig(t *testing.T) {
	n, e := parseNode(testLink())
	if e != nil {
		t.Fatal(e)
	}
	b, e := n.config(12345, "127.0.0.1:23456", "secret")
	if e != nil {
		t.Fatal(e)
	}
	var c map[string]any
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	out := c["outbounds"].([]any)
	if len(out) != 2 {
		t.Fatal("unexpected outbound count")
	}
	if got := out[0].(map[string]any)["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["dialerProxy"]; got != "dae-exit" {
		t.Fatal(got)
	}
	if strings.Contains(string(b), `"protocol":"freedom"`) {
		t.Fatal("unprotected direct outbound")
	}
	if n.outbound["streamSettings"].(map[string]any)["sockopt"] != nil {
		t.Fatal("config mutation")
	}
}

func TestInvalidLinks(t *testing.T) {
	for _, suffix := range []string{"&mode=bad", "&flow=xtls-rprx-vision", "&sid=z", "&sid=1", "&sid=001122334455667788", "&extra=[]", "&extra=" + url.QueryEscape(`{"downloadSettings":{}}`), "&mode=auto&mode=packet-up", "&encryption=other"} {
		t.Run(suffix, func(t *testing.T) {
			link := strings.Split(testLink(), "#")[0] + suffix
			if _, e := parseNode(link); e == nil {
				t.Fatal("accepted", suffix)
			}
		})
	}
}

func TestImportHasNoWorker(t *testing.T) {
	d, p, e := NewVLESS(&D.ExtraOption{}, direct.SymmetricDirect, testLink())
	if e != nil {
		t.Fatal(e)
	}
	x := d.(*Dialer)
	defer x.Close()
	if p.Protocol != "vless" || p.Name != "test" || len(x.workers) != 0 {
		t.Fatal("wrong metadata or eager process")
	}
}
