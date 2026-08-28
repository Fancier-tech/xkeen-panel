package xkeen

// normalizeXHTTPOutbound keeps provider XHTTP profiles compatible across Xray
// releases. Xray 26.2.6 understands sessionPlacement/sessionKey, while some
// current subscriptions emit sessionIDPlacement/sessionIDKey.
//
// Xray 26.2.6 also rejects an explicitly configured seqPlacement:"path" when
// sessionPlacement resolves to "path" because of a parser switch-case bug.
// Omitting seqPlacement has exactly the intended semantics: its default is
// "path". Newer cores also default it to path.
func normalizeXHTTPOutbound(ob map[string]interface{}) {
	if ob == nil {
		return
	}
	stream, _ := ob["streamSettings"].(map[string]interface{})
	if stream == nil {
		return
	}
	network, _ := stream["network"].(string)
	if network != "xhttp" && network != "splithttp" {
		return
	}
	xs, _ := stream["xhttpSettings"].(map[string]interface{})
	if xs == nil {
		return
	}

	normalizeXHTTPMap(xs)
	if extra, _ := xs["extra"].(map[string]interface{}); extra != nil {
		normalizeXHTTPMap(extra)
	}
}

func normalizeXHTTPMap(m map[string]interface{}) {
	if m == nil {
		return
	}

	// New spelling -> spelling understood by Xray 26.2.x.
	if v, ok := m["sessionIDPlacement"]; ok {
		if _, exists := m["sessionPlacement"]; !exists {
			m["sessionPlacement"] = v
		}
	}
	if v, ok := m["sessionIDKey"]; ok {
		if _, exists := m["sessionKey"]; !exists {
			m["sessionKey"] = v
		}
	}

	seq, _ := m["seqPlacement"].(string)
	if seq != "path" {
		return
	}

	session, hasLegacy := m["sessionPlacement"].(string)
	if !hasLegacy || session == "" || session == "path" {
		delete(m, "seqPlacement")
	}
}
