package xkeen

import (
	"fmt"
	"log"
	"strings"

	"xkeen-panel/internal/models"
)

// ApplyServer writes the selected entry into the core config and validates the
// result before anyone restarts on top of it. An entry may be one ordinary
// server or a provider-owned Xray balancer profile.
func ApplyServer(rt Runtime, outboundsPath string, server *models.Server) error {
	if IsXrayProfile(server) {
		return ApplyXrayProfile(rt, outboundsPath, server)
	}

	// A provider profile leaves several outbounds and a balancer behind. When the
	// user selects a normal VLESS again, collapse that layout deliberately rather
	// than letting UpdateOutbound reject/partially rewrite the pool.
	if providerProfileActive(outboundsPath) {
		return ApplySingleFromProviderProfile(rt, outboundsPath, server)
	}

	if err := ensureOutboundsContainer(outboundsPath); err != nil {
		return err
	}

	if err := UpdateOutbound(outboundsPath, server); err != nil {
		return err
	}

	if !rt.Installed || rt.Dispatcher == "" {
		return nil
	}

	output, err := TestConfig(rt.Dispatcher, rt.Core)
	if err == nil {
		return nil
	}

	if rbErr := RestoreBackup(outboundsPath); rbErr != nil {
		log.Printf("[APPLY] Конфиг не прошёл проверку и откат не удался: %v", rbErr)
		return fmt.Errorf("конфигурация %s не прошла проверку, откат не удался: %v (%s)", rt.Core, rbErr, output)
	}

	log.Printf("[APPLY] Конфиг не прошёл проверку — выполнен откат")

	return fmt.Errorf("конфигурация %s не прошла проверку, изменения отменены: %s", rt.Core, TailLines(output, 4))
}

// ensureOutboundsContainer initializes a fresh XKeen 04_outbounds.json.
// Some installations ship this file as just `{}`. UpdateOutbound deliberately
// treats a malformed/missing outbounds field as an error, so normalize only the
// valid empty-object case here before applying the first subscription server.
func ensureOutboundsContainer(path string) error {
	config, err := ReadOutboundsConfig(path)
	if err != nil {
		return err
	}

	if _, exists := config["outbounds"]; exists {
		return nil
	}
	if len(config) != 0 {
		return fmt.Errorf("outbounds не найдены в непустом конфиге")
	}

	config["outbounds"] = []interface{}{}
	return WriteOutboundsConfig(path, config)
}

// TailLines trims validator output to something a UI can show. The tail is what
// matters: `xray -test` logs a line per config file it reads and only then
// prints the failure, so the head is noise.
func TailLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")

	kept := make([]string, 0, n)
	for i := len(lines) - 1; i >= 0 && len(kept) < n; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			kept = append([]string{line}, kept...)
		}
	}

	if len(kept) == 0 {
		return "вывод пуст"
	}

	return strings.Join(kept, "; ")
}
