package xkeen

import "testing"

func TestNormalizeXHTTPPathPlacementForXray262(t *testing.T) {
	ob := map[string]interface{}{
		"streamSettings": map[string]interface{}{
			"network": "xhttp",
			"xhttpSettings": map[string]interface{}{
				"mode": "packet-up",
				"extra": map[string]interface{}{
					"sessionIDPlacement": "path",
					"seqPlacement":       "path",
				},
			},
		},
	}

	normalizeXHTTPOutbound(ob)

	extra := ob["streamSettings"].(map[string]interface{})["xhttpSettings"].(map[string]interface{})["extra"].(map[string]interface{})
	if extra["sessionPlacement"] != "path" {
		t.Fatalf("sessionPlacement = %v, want path", extra["sessionPlacement"])
	}
	if _, exists := extra["seqPlacement"]; exists {
		t.Fatal("explicit seqPlacement=path must be removed for Xray 26.2.x compatibility")
	}
	if extra["sessionIDPlacement"] != "path" {
		t.Fatal("provider's new spelling must be preserved for newer cores")
	}
}

func TestNormalizeXHTTPKeepsNonPathSeqPlacement(t *testing.T) {
	ob := map[string]interface{}{
		"streamSettings": map[string]interface{}{
			"network": "xhttp",
			"xhttpSettings": map[string]interface{}{
				"extra": map[string]interface{}{
					"sessionIDPlacement": "header",
					"seqPlacement":       "query",
				},
			},
		},
	}

	normalizeXHTTPOutbound(ob)
	extra := ob["streamSettings"].(map[string]interface{})["xhttpSettings"].(map[string]interface{})["extra"].(map[string]interface{})
	if extra["sessionPlacement"] != "header" || extra["seqPlacement"] != "query" {
		t.Fatalf("non-path placement changed: %#v", extra)
	}
}
