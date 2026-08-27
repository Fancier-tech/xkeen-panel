package xkeen

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"xkeen-panel/internal/models"
)

// ParseXraySubscription imports Xray JSON subscriptions that contain either a
// single config object or an array of config objects. Some providers (including
// HAPP-oriented subscriptions) return several ready-made profiles, each with one
// or more VLESS outbounds.
func ParseXraySubscription(content string) ([]models.Server, error) {
	var raw interface{}
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return nil, fmt.Errorf("не Xray JSON: %w", err)
	}

	var configs []map[string]interface{}
	switch v := raw.(type) {
	case map[string]interface{}:
		configs = append(configs, v)
	case []interface{}:
		for _, item := range v {
			if cfg, ok := item.(map[string]interface{}); ok {
				configs = append(configs, cfg)
			}
		}
	default:
		return nil, fmt.Errorf("неподдерживаемая структура Xray JSON")
	}

	var servers []models.Server
	seen := make(map[string]bool)
	for _, cfg := range configs {
		remarks, _ := cfg["remarks"].(string)
		remarks = strings.TrimSpace(remarks)

		outbounds, _ := cfg["outbounds"].([]interface{})
		var vlessOutbounds []map[string]interface{}
		for _, rawOutbound := range outbounds {
			outbound, ok := rawOutbound.(map[string]interface{})
			if !ok {
				continue
			}
			protocol, _ := outbound["protocol"].(string)
			if protocol == "vless" {
				vlessOutbounds = append(vlessOutbounds, outbound)
			}
		}

		for i, outbound := range vlessOutbounds {
			name := remarks
			if name == "" {
				name, _ = outbound["tag"].(string)
			}
			if len(vlessOutbounds) > 1 && name != "" {
				name = fmt.Sprintf("%s / %d", name, i+1)
			}

			server, err := xrayOutboundToServer(outbound, name)
			if err != nil {
				continue
			}
			if seen[server.RawURI] {
				continue
			}
			seen[server.RawURI] = true
			server.ID = len(servers)
			server.Country = detectCountry(server.Name)
			servers = append(servers, *server)
		}
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("в Xray JSON не найдено ни одного поддерживаемого VLESS outbound")
	}
	return servers, nil
}

func xrayOutboundToServer(outbound map[string]interface{}, name string) (*models.Server, error) {
	settings, _ := outbound["settings"].(map[string]interface{})
	if settings == nil {
		return nil, fmt.Errorf("VLESS outbound без settings")
	}

	address, port, uuid, ok := readProxyEndpoint(outbound)
	if !ok || address == "" || uuid == "" {
		return nil, fmt.Errorf("VLESS outbound без address/uuid")
	}
	if port == 0 {
		port = 443
	}

	flow := ""
	encryption := "none"
	if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
		if entry, _ := vnext[0].(map[string]interface{}); entry != nil {
			if users, _ := entry["users"].([]interface{}); len(users) > 0 {
				if user, _ := users[0].(map[string]interface{}); user != nil {
					flow, _ = user["flow"].(string)
					if e, _ := user["encryption"].(string); e != "" {
						encryption = e
					}
				}
			}
		}
	} else {
		flow, _ = settings["flow"].(string)
		if e, _ := settings["encryption"].(string); e != "" {
			encryption = e
		}
	}
	packetEncoding, _ := settings["packetEncoding"].(string)

	stream, _ := outbound["streamSettings"].(map[string]interface{})
	network := "tcp"
	security := ""
	q := url.Values{}
	if stream != nil {
		if s, _ := stream["network"].(string); s != "" {
			network = s
		}
		security, _ = stream["security"].(string)
	}
	q.Set("encryption", encryption)
	q.Set("type", network)
	if flow != "" {
		q.Set("flow", flow)
	}
	if packetEncoding != "" {
		q.Set("packetEncoding", packetEncoding)
	}
	if security != "" && security != "none" {
		q.Set("security", security)
	}

	if stream != nil {
		if security == "reality" {
			if rs, _ := stream["realitySettings"].(map[string]interface{}); rs != nil {
				setString(q, "sni", rs["serverName"])
				setString(q, "fp", rs["fingerprint"])
				setString(q, "pbk", rs["publicKey"])
				setString(q, "sid", rs["shortId"])
				setString(q, "spx", rs["spiderX"])
			}
		}
		if security == "tls" {
			if ts, _ := stream["tlsSettings"].(map[string]interface{}); ts != nil {
				setString(q, "sni", ts["serverName"])
				setString(q, "fp", ts["fingerprint"])
				if alpn := stringSlice(ts["alpn"]); len(alpn) > 0 {
					q.Set("alpn", strings.Join(alpn, ","))
				}
			}
		}

		switch canonicalNetwork(network) {
		case "ws":
			if ws, _ := stream["wsSettings"].(map[string]interface{}); ws != nil {
				setString(q, "path", ws["path"])
				if headers, _ := ws["headers"].(map[string]interface{}); headers != nil {
					setString(q, "host", headers["Host"])
				}
			}
		case "grpc":
			if grpc, _ := stream["grpcSettings"].(map[string]interface{}); grpc != nil {
				setString(q, "path", grpc["serviceName"])
				if multi, _ := grpc["multiMode"].(bool); multi {
					q.Set("mode", "multi")
				}
			}
		case "h2":
			if hs, _ := stream["httpSettings"].(map[string]interface{}); hs != nil {
				setString(q, "path", hs["path"])
				if hosts := stringSlice(hs["host"]); len(hosts) > 0 {
					q.Set("host", hosts[0])
				}
			}
		case "xhttp":
			if xs, _ := stream["xhttpSettings"].(map[string]interface{}); xs != nil {
				setString(q, "path", xs["path"])
				setString(q, "host", xs["host"])
				setString(q, "mode", xs["mode"])
				extra := make(map[string]interface{})
				for k, v := range xs {
					if k != "path" && k != "host" && k != "mode" {
						extra[k] = v
					}
				}
				if len(extra) > 0 {
					if b, err := json.Marshal(extra); err == nil {
						q.Set("extra", string(b))
					}
				}
			}
		}
	}

	if name == "" {
		name = address
	}
	u := &url.URL{
		Scheme:   "vless",
		User:     url.User(uuid),
		Host:     address + ":" + strconv.Itoa(port),
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return &models.Server{
		Name:     name,
		Address:  address,
		Port:     port,
		Protocol: "vless",
		Latency:  -1,
		RawURI:   u.String(),
	}, nil
}

func setString(q url.Values, key string, value interface{}) {
	if s, _ := value.(string); s != "" {
		q.Set(key, s)
	}
}

func stringSlice(v interface{}) []string {
	switch x := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	case string:
		if x != "" {
			return []string{x}
		}
	}
	return nil
}
