package xkeen

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"xkeen-panel/internal/models"
)

const providerProfileMarkerSuffix = ".provider-profile"

func providerProfileMarkerPath(outboundsPath string) string {
	return outboundsPath + providerProfileMarkerSuffix
}

func IsXrayProfile(server *models.Server) bool {
	return server != nil && (server.EntryType == "profile" || strings.HasPrefix(server.RawURI, xrayProfileScheme))
}

func providerProfileActive(outboundsPath string) bool {
	_, err := os.Stat(providerProfileMarkerPath(outboundsPath))
	return err == nil
}

func ApplyXrayProfile(rt Runtime, outboundsPath string, server *models.Server) error {
	profile, err := decodeXrayProfile(server.RawURI)
	if err != nil {
		return err
	}

	var profileNodes []interface{}
	for _, raw := range asSlice(profile["outbounds"]) {
		ob, ok := raw.(map[string]interface{})
		if !ok || ob["protocol"] != "vless" {
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
	for i, raw := range profileNodes {
		profileNodes[i] = mergeOutbound(template, raw.(map[string]interface{}))
	}
	currentProxyTags := proxyOutboundTags(currentOutbounds)
	outCfg["outbounds"] = append(profileNodes, serviceOutbounds(currentOutbounds)...)

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
		return fmt.Errorf("не найдено правило XKeen для balancer %q", targetBalancer)
	}

	doc.routing["balancers"] = cloneSlice(sourceBalancers)
	doc.config["routing"] = doc.routing
	copyOptionalProfileBlock(doc.config, profile, "observatory")
	copyOptionalProfileBlock(doc.config, profile, "burstObservatory")

	if err := applyConfigs(rt, map[string]map[string]interface{}{
		outboundsPath: outCfg,
		doc.path:      doc.config,
	}); err != nil {
		return err
	}
	return os.WriteFile(providerProfileMarkerPath(outboundsPath), []byte("1\n"), 0600)
}

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

	doc, err := findRoutingDoc(rt, func(rule map[string]interface{}) bool {
		_, ok := rule["balancerTag"]
		return ok
	})
	if err != nil {
		return err
	}
	currentBalancerTags := balancerTags(doc.routing)
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
		return fmt.Errorf("не найдено правило активного balancer")
	}
	delete(doc.routing, "balancers")
	doc.config["routing"] = doc.routing
	delete(doc.config, "observatory")
	delete(doc.config, "burstObservatory")

	if err := applyConfigs(rt, map[string]map[string]interface{}{
		outboundsPath: outCfg,
		doc.path:      doc.config,
	}); err != nil {
		return err
	}
	if err := os.Remove(providerProfileMarkerPath(outboundsPath)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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
