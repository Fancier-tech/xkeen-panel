package xkeen

import (
	"strings"
	"testing"
)

func TestParseXraySubscriptionArray(t *testing.T) {
	content := `[
  {
    "remarks": "Свободный интернет #1",
    "outbounds": [
      {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
          "vnext": [{
            "address": "one.example",
            "port": 443,
            "users": [{
              "id": "11111111-1111-1111-1111-111111111111",
              "encryption": "none",
              "flow": "xtls-rprx-vision"
            }]
          }],
          "packetEncoding": "xudp"
        },
        "streamSettings": {
          "network": "tcp",
          "security": "reality",
          "realitySettings": {
            "serverName": "www.example.com",
            "fingerprint": "chrome",
            "publicKey": "PUBKEY1",
            "shortId": "abcd"
          }
        }
      },
      {
        "tag": "proxy-2",
        "protocol": "vless",
        "settings": {
          "address": "two.example",
          "port": 8443,
          "id": "22222222-2222-2222-2222-222222222222",
          "encryption": "none"
        },
        "streamSettings": {
          "network": "tcp"
        }
      }
    ]
  }
]`

	servers, err := ParseXraySubscription(content)
	if err != nil {
		t.Fatalf("ParseXraySubscription: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(servers))
	}
	if servers[0].Name != "Свободный интернет #1 / 1" || servers[1].Name != "Свободный интернет #1 / 2" {
		t.Fatalf("unexpected names: %q, %q", servers[0].Name, servers[1].Name)
	}
	if servers[0].Address != "one.example" || servers[1].Address != "two.example" {
		t.Fatalf("unexpected addresses")
	}

	p, err := ParseVLESS(servers[0].RawURI)
	if err != nil {
		t.Fatalf("ParseVLESS: %v", err)
	}
	if p.Security != "reality" || p.PublicKey != "PUBKEY1" || p.ShortID != "abcd" || p.Fingerprint != "chrome" {
		t.Fatalf("reality settings lost: %+v", p)
	}
	if p.Flow != "xtls-rprx-vision" || p.PacketEncoding != "xudp" {
		t.Fatalf("VLESS settings lost: %+v", p)
	}

	out := buildOutboundFromURI(p, "vless-reality", formatVNext)
	settings := out["settings"].(map[string]interface{})
	if settings["packetEncoding"] != "xudp" {
		t.Fatalf("packetEncoding not restored: %#v", settings["packetEncoding"])
	}
}

func TestParseXraySubscriptionKeepsBalancerProfileTogether(t *testing.T) {
	content := `[
  {
    "remarks": "Свободный интернет #3 (безлимит)",
    "outbounds": [
      {"tag":"proxy","protocol":"vless","settings":{"address":"one.example","port":443,"id":"11111111-1111-1111-1111-111111111111"},"streamSettings":{"network":"tcp"}},
      {"tag":"proxy-2","protocol":"vless","settings":{"address":"two.example","port":443,"id":"22222222-2222-2222-2222-222222222222"},"streamSettings":{"network":"tcp"}},
      {"tag":"proxy-3","protocol":"vless","settings":{"address":"three.example","port":443,"id":"33333333-3333-3333-3333-333333333333"},"streamSettings":{"network":"tcp"}}
    ],
    "routing": {
      "balancers": [{
        "tag": "LB",
        "selector": ["proxy"],
        "strategy": {"type":"leastLoad"},
        "fallbackTag": "proxy"
      }],
      "rules": [{"type":"field","network":"tcp,udp","balancerTag":"LB"}]
    },
    "burstObservatory": {"subjectSelector":["proxy"]}
  }
]`

	servers, err := ParseXraySubscription(content)
	if err != nil {
		t.Fatalf("ParseXraySubscription: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d entries, want one profile", len(servers))
	}
	p := servers[0]
	if p.EntryType != "profile" || !p.Balanced || p.MemberCount != 3 {
		t.Fatalf("profile metadata lost: %+v", p)
	}
	if p.Name != "Свободный интернет #3 (безлимит)" {
		t.Fatalf("profile name = %q", p.Name)
	}
	if !strings.HasPrefix(p.RawURI, xrayProfileScheme) {
		t.Fatalf("profile payload not preserved")
	}
	decoded, err := decodeXrayProfile(p.RawURI)
	if err != nil {
		t.Fatalf("decodeXrayProfile: %v", err)
	}
	routing := decoded["routing"].(map[string]interface{})
	if len(asSlice(routing["balancers"])) != 1 {
		t.Fatal("balancer was not preserved")
	}
	if _, ok := decoded["burstObservatory"]; !ok {
		t.Fatal("burstObservatory was not preserved")
	}
}

func TestXraySubscriptionDeduplicates(t *testing.T) {
	config := `{"remarks":"One","outbounds":[{"protocol":"vless","settings":{"address":"a.example","port":443,"id":"11111111-1111-1111-1111-111111111111"},"streamSettings":{"network":"tcp"}}]}`
	content := "[" + config + "," + config + "]"
	servers, err := ParseXraySubscription(content)
	if err != nil {
		t.Fatalf("ParseXraySubscription: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
}

func TestUnsupportedPlaceholder(t *testing.T) {
	servers, err := ParseSubscription("dmxlc3M6Ly9kdW1teUAwLjAuMC4wOjEjQXBwJTIwbm90JTIwc3VwcG9ydGVk")
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if !isUnsupportedPlaceholder(servers) {
		t.Fatalf("placeholder not detected: %+v", servers)
	}
	if !strings.Contains(strings.ToLower(servers[0].Name), "app%20not%20supported") && servers[0].Address != "0.0.0.0" {
		t.Fatal("test fixture is not the expected placeholder")
	}
}
