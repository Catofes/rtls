package rtls

import (
	"encoding/hex"
	"io/ioutil"
	"strings"
	"testing"
)

func TestGetHostnameFromCurlClientHello(t *testing.T) {
	encoded, err := ioutil.ReadFile("testdata/curl-clienthello.hex")
	if err != nil {
		t.Fatalf("read ClientHello fixture: %v", err)
	}
	clientHello, err := hex.DecodeString(strings.Join(strings.Fields(string(encoded)), ""))
	if err != nil {
		t.Fatalf("decode ClientHello fixture: %v", err)
	}
	if len(clientHello) != 1565 {
		t.Fatalf("ClientHello fixture has %d bytes, want 1565", len(clientHello))
	}

	got, err := GetHostname(clientHello)
	if err != nil {
		t.Fatalf("GetHostname returned an error: %v", err)
	}
	if got != "rtls-parser.test" {
		t.Fatalf("GetHostname = %q, want %q", got, "rtls-parser.test")
	}
}

func TestSNIParserRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name  string
		parse func() error
	}{
		{
			name: "truncated server name list",
			parse: func() error {
				_, err := GetSNIBlock([]byte{0, 0})
				return err
			},
		},
		{
			name: "server name exceeds list",
			parse: func() error {
				_, err := GetSNIBlock([]byte{0, 4, 0, 0, 5, 'a'})
				return err
			},
		},
		{
			name: "extension exceeds block",
			parse: func() error {
				_, err := GetSNBlock([]byte{0, 4, 0, 0, 0, 8})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.parse(); err == nil {
				t.Fatal("expected malformed input to be rejected")
			}
		})
	}
}

func TestValidateTarget(t *testing.T) {
	for _, raw := range []string{
		"direct://127.0.0.1:80",
		"tcp://edge-cert@127.0.0.1:443",
		"tls://edge-cert@example.com:443",
	} {
		if _, err := validateTarget(raw); err != nil {
			t.Fatalf("validateTarget(%q) returned an error: %v", raw, err)
		}
	}

	for _, raw := range []string{
		"tcp://127.0.0.1:443",
		"tls://edge-cert@example.com",
		"http://example.com:80",
	} {
		if _, err := validateTarget(raw); err == nil {
			t.Fatalf("validateTarget(%q) succeeded, want error", raw)
		}
	}
}
