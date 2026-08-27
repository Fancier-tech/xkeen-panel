package xkeen

import "testing"

func TestParseClashVLESSSubscription(t *testing.T) {
	content := `proxies:
  - name: Test Reality
    type: vless
    server: example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    network: tcp
    tls: true
    servername: example.org
    client-fingerprint: chrome
    flow: xtls-rprx-vision
    reality-opts:
      public-key: PUBKEY
      short-id: abcd
`

	servers, err := ParseClashSubscription(content)
	if err != nil {
		t.Fatalf("ParseClashSubscription: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	s := servers[0]
	if s.Protocol != "vless" || s.Address != "example.com" || s.Port != 443 {
		t.Fatalf("unexpected server: %+v", s)
	}
	if s.RawURI == "" {
		t.Fatal("RawURI is empty")
	}
	p, err := ParseVLESS(s.RawURI)
	if err != nil {
		t.Fatalf("ParseVLESS: %v", err)
	}
	if p.UUID != "11111111-1111-1111-1111-111111111111" || p.Security != "reality" || p.PublicKey != "PUBKEY" || p.ShortID != "abcd" || p.Flow != "xtls-rprx-vision" {
		t.Fatalf("unexpected VLESS params: %+v", p)
	}
}

func TestIsUnsupportedPlaceholder(t *testing.T) {
	servers, err := ParseSubscription("dmxlc3M6Ly9kdW1teUAwLjAuMC4wOjEjQXBwJTIwbm90JTIwc3VwcG9ydGVk")
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if !isUnsupportedPlaceholder(servers) {
		t.Fatal("expected placeholder to be detected")
	}
}
