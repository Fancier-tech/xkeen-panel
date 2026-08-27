package xkeen

import (
	"encoding/json"
	"fmt"
	"strings"

	"xkeen-panel/internal/models"
)

const providerProfileMarker = "xkeen_provider_profile"

func IsXrayProfile(server *models.Server) bool {
	return server != nil && (server.EntryType == "profile" || strings.HasPrefix(server.RawURI, xrayProfileScheme))
}

func providerProfileActive(outboundsPath string) bool {
	cfg, err := ReadOutboundsConfig(outboundsPath)
	if err != nil {
		return false
	}
	active, _ := cfg[providerProfileMarker].(bool)
	return active
}

// ApplyXrayProfile installs a provider-owned balancer profile while keeping
// XKeen's own inbounds and routing rules. Only the profile's proxy outbounds,
// balancer definition and observatory blocks are imported; the provider's
// standalone-client inbounds/rules are deliberately not copied.
func ApplyXrayProfile(rt Runtime, outboundsPath string, server *models.Server) error {
	profile, err := decodeXrayProfile(server.RawURI)
	if err != nil {
		return err
	}

	sourceOutbounds := asSlice(profile["outbounds"])
	var profileNodes []interface{}
	for _, raw := range sourceOutbounds {
		ob, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		protocol, _ := ob["protocol"].(string)
		if protocol != "vless" {
			continue
		}
		profileNodes = append(profileNodes, cloneMap(ob))
	}
	if len(profileNodes) == 0 {
		return fmt.Errorf("в профиле %q нет VLESS outbound", server.Name)
	}

	sourceRouting, _ := profile["routing"].(map[string]interface{})
	if sourceRouting == nil {
		return fmt.Errorf("в профиле %q нет routing", server.Name)
	}
	sourceBalancers := asSlice(sourceRouting["balancers"])
	if len(sourceBalancers) == 0 {
		return fmt.Errorf("в профиле %q нет balancer", server.Name)
	}
	firstBalancer, _ := sourceBalancers[0].(map[string]interface{})
	targetBalancer, _ := firstBalancer["tag"].(string)
	if targetBalancer == "" {
		return fmt.Errorf("в профиле %q balancer без tag", server.Name)
	}

	outCfg, err := ReadOutboundsConfig(outboundsPath)
	if err != nil {
		return err
	}
	currentOutbounds, _ := outCfg["outbounds"].([]interface{})
	_, template := findProxyOutbound(currentOutbounds)

	// Preserve Keenetic-specific stream options such as sockopt from the current
	// template, but keep every provider field in each imported outbound.
	for i, raw := range profileNodes {
		ob := raw.(map[string]interface{})
		profileNodes[i] = mergeOutbound(template, ob)
	}

	currentProxyTags := proxyOutboundTags(currentOutbounds)
	outCfg["outbounds"] = append(profileNodes, serviceOutbounds(currentOutbounds)...)
	outCfg[providerProfileMarker] = true

	doc, err := findRoutingDoc(rt, func(rule map[string]interface{}) bool {
		if tag, _ := rule["outboundTag"].(string); containsString(currentProxyTags, tag) {
			return true
		}
		_, hasBalancer := rule["balancerTag"]
		return hasBalancer
	})
	if err != nil {
		return err
	}

	oldBalancerTags := balancerTags(doc.routing)
	changed := 0
	for _, raw := range asSlice(doc.routing["rules"]) {
		rule, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if tag, _ := rule["outboundTag"].(string); containsString(currentProxyTags, tag) {
			delete(rule, "outboundTag")
			rule["balancerTag"] = targetBalancer
			changed++
			continue
		}
		if tag, _ := rule["balancerTag"].(string); containsString(oldBalancerTags, tag) {
			rule["balancerTag"] = targetBalancer
			changed++
		}
	}
	if changed == 0 {
		return fmt.Errorf("не найдено правило XKeen, которое можно направить на balancer %q", targetBalancer)
	}

	doc.routing["balancers"] = cloneSlice(sourceBalancers)
	doc.config["routing"] = doc.routing
	copyOptionalProfileBlock(doc.config, profile, "observatory")
	copyOptionalProfileBlock(doc.config, profile, "burstObservatory")

	return applyConfigs(rt, map[string]map[string]interface{}{
		outboundsPath: outCfg,
		doc.path:      doc.config,
	})
}

// ApplySingleFromProviderProfile leaves a provider profile and restores a normal
// one-outbound XKeen layout. It is intentionally separate from panel-managed
// pool mode: the latter has its own PoolStore and handlers.
func ApplySingleFromProviderProfile(rt Runtime, outboundsPath string, server *models.Server) error {
	if server == nil || server.RawURI == "" {
		return fmt.Errorf("нужен VLESS сервер")
	}
	params, err := ParseVLESS(server.RawURI)
	if err != nil {
		return fmt.Errorf("ошибка парсинга URI: %w", err)
	}

	outCfg, err := ReadOutboundsConfig(outboundsPath)
	if err != nil {
		return err
	}
	currentOutbounds, _ := outCfg["outbounds"].([]interface{})
	_, template := findProxyOutbound(currentOutbounds)
	tag := outboundTag(template)
	single := mergeOutbound(template, buildOutboundFromURI(params, tag, detectOutboundFormat(template)))
	outCfg["outbounds"] = append([]interface{}{single}, serviceOutbounds(currentOutbounds)...)
	delete(outCfg, providerProfileMarker)

	currentBalancerTags := []string{}
	doc, err := findRoutingDoc(rt, func(rule map[string]interface{}) bool {
		_, ok := rule["balancerTag"]
		return ok
	})
	if err != nil {
		return err
	}
	currentBalancerTags = balancerTags(doc.routing)
	changed := 0
	for _, raw := range asSlice(doc.routing["rules"]) {
		rule, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if b, _ := rule["balancerTag"].(string); containsString(currentBalancerTags, b) {
			delete(rule, "balancerTag")
			rule["outboundTag"] = tag
			changed++
		}
	}
	if changed == 0 {
		return fmt.Errorf("не найдено правило, ведущее на активный balancer")
	}
	delete(doc.routing, "balancers")
	doc.config["routing"] = doc.routing
	delete(doc.config, "observatory")
	delete(doc.config, "burstObservatory")

	return applyConfigs(rt, map[string]map[string]interface{}{
		outboundsPath: outCfg,
		doc.path:      doc.config,
	})
}

func balancerTags(routing map[string]interface{}) []string {
	var tags []string
	for _, raw := range asSlice(routing["balancers"]) {
		if b, ok := raw.(map[string]interface{}); ok {
			if tag, _ := b["tag"].(string); tag != "" {
				tags = append(tags, tag)
			}
		}
	}
	return tags
}

func containsString(list []string, value string) bool {
	if value == "" {
		return false
	}
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func cloneMap(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return nil
	}
	b, _ := json.Marshal(src)
	var dst map[string]interface{}
	_ = json.Unmarshal(b, &dst)
	return dst
}

func cloneSlice(src []interface{}) []interface{} {
	b, _ := json.Marshal(src)
	var dst []interface{}
	_ = json.Unmarshal(b, &dst)
	return dst
}

func copyOptionalProfileBlock(dst, src map[string]interface{}, key string) {
	if value, ok := src[key]; ok {
		b, _ := json.Marshal(value)
		var cloned interface{}
		_ = json.Unmarshal(b, &cloned)
		dst[key] = cloned
	} else {
		delete(dst, key)
	}
}
