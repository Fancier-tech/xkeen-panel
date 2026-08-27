package xkeen

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"xkeen-panel/internal/models"
)

type SubscriptionManager struct {
	dataDir string
	data    *models.SubscriptionData
	mu      sync.RWMutex
}

func NewSubscriptionManager(dataDir string) *SubscriptionManager {
	return &SubscriptionManager{
		dataDir: dataDir,
		data:    &models.SubscriptionData{},
	}
}

func (sm *SubscriptionManager) filePath() string {
	return filepath.Join(sm.dataDir, "subscription.json")
}

func (sm *SubscriptionManager) hwidPath() string {
	return filepath.Join(filepath.Dir(sm.dataDir), "hwid")
}

func (sm *SubscriptionManager) Load() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	data, err := os.ReadFile(sm.filePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, sm.data)
}

func (sm *SubscriptionManager) Save() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if err := os.MkdirAll(sm.dataDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sm.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(sm.filePath(), data, 0600)
}

// UpdateURL accepts either a subscription URL or one standalone proxy URI.
// A standalone URI is stored as a manual entry and has no refresh URL.
func (sm *SubscriptionManager) UpdateURL(raw string) ([]models.Server, error) {
	raw = strings.TrimSpace(raw)
	var servers []models.Server
	var err error
	storedURL := raw

	if strings.HasPrefix(raw, "vless://") || strings.HasPrefix(raw, "vmess://") || strings.HasPrefix(raw, "trojan://") || strings.HasPrefix(raw, "ss://") {
		servers, err = ParseSubscription(raw)
		storedURL = ""
	} else {
		servers, err = sm.downloadAndParse(raw)
	}
	if err != nil {
		return nil, err
	}

	sm.mu.Lock()
	sm.data.URL = storedURL
	sm.applyRefreshLocked(servers)
	sm.mu.Unlock()
	return servers, sm.Save()
}

func (sm *SubscriptionManager) Refresh() ([]models.Server, error) {
	sm.mu.RLock()
	url := sm.data.URL
	sm.mu.RUnlock()
	if url == "" {
		return nil, fmt.Errorf("URL подписки не задан")
	}
	servers, err := sm.downloadAndParse(url)
	if err != nil {
		return nil, err
	}
	sm.mu.Lock()
	sm.applyRefreshLocked(servers)
	sm.mu.Unlock()
	return servers, sm.Save()
}

// applyRefreshLocked keeps ordinary nodes by RawURI. Provider profiles are
// matched by their display name first because their encoded raw configuration
// changes whenever the provider rotates a member inside the same profile.
func (sm *SubscriptionManager) applyRefreshLocked(servers []models.Server) {
	var activeURI, activeName, activeType string
	if sm.data.ActiveID >= 0 && sm.data.ActiveID < len(sm.data.Servers) {
		active := sm.data.Servers[sm.data.ActiveID]
		activeURI = active.RawURI
		activeName = active.Name
		activeType = active.EntryType
	}

	carryOverrides(sm.data.Servers, servers)
	sm.data.LastUpdated = time.Now()
	sm.data.Servers = servers

	newActive := 0
	for i := range servers {
		if activeType == "profile" && servers[i].EntryType == "profile" && servers[i].Name == activeName {
			newActive = i
			break
		}
		if activeType != "profile" && activeURI != "" && servers[i].RawURI == activeURI {
			newActive = i
			break
		}
	}
	sm.data.ActiveID = newActive
	for i := range sm.data.Servers {
		sm.data.Servers[i].Active = i == newActive
	}
}

func carryOverrides(old, fresh []models.Server) {
	if len(old) == 0 {
		return
	}
	overrides := make(map[string]string, len(old))
	for i := range old {
		if old[i].CountryOverride != "" && old[i].RawURI != "" {
			overrides[old[i].RawURI] = old[i].CountryOverride
		}
	}
	for i := range fresh {
		if ov, ok := overrides[fresh[i].RawURI]; ok {
			fresh[i].CountryOverride = ov
		}
	}
}

func (sm *SubscriptionManager) GetData() models.SubscriptionData {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	d := *sm.data
	d.Servers = append([]models.Server(nil), sm.data.Servers...)
	return d
}

func (sm *SubscriptionManager) GetServers() []models.Server {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]models.Server, len(sm.data.Servers))
	copy(result, sm.data.Servers)
	return result
}

func (sm *SubscriptionManager) UpdateLatencies(checked []models.Server) {
	sm.mu.Lock()
	byURI := make(map[string]int, len(checked))
	for _, c := range checked {
		if c.RawURI != "" {
			byURI[c.RawURI] = c.Latency
		}
	}
	now := time.Now()
	for i := range sm.data.Servers {
		if lat, ok := byURI[sm.data.Servers[i].RawURI]; ok {
			sm.data.Servers[i].Latency = lat
			sm.data.Servers[i].LastChecked = now
		}
	}
	data, err := json.MarshalIndent(sm.data, "", "  ")
	sm.mu.Unlock()
	if err != nil {
		return
	}
	if err := os.MkdirAll(sm.dataDir, 0700); err == nil {
		os.WriteFile(sm.filePath(), data, 0600)
	}
}

func (sm *SubscriptionManager) SetCountryOverride(id int, country string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if id < 0 || id >= len(sm.data.Servers) {
		return fmt.Errorf("сервер с id %d не найден", id)
	}
	sm.data.Servers[id].CountryOverride = strings.ToUpper(strings.TrimSpace(country))
	data, err := json.MarshalIndent(sm.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sm.dataDir, 0700); err != nil {
		return err
	}
	return os.WriteFile(sm.filePath(), data, 0600)
}

func (sm *SubscriptionManager) SetActive(id int) (*models.Server, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if id < 0 || id >= len(sm.data.Servers) {
		return nil, fmt.Errorf("сервер с id %d не найден", id)
	}
	sm.data.ActiveID = id
	for i := range sm.data.Servers {
		sm.data.Servers[i].Active = i == id
	}
	server := sm.data.Servers[id]
	data, err := json.MarshalIndent(sm.data, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sm.dataDir, 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(sm.filePath(), data, 0600); err != nil {
		return nil, err
	}
	return &server, nil
}

func (sm *SubscriptionManager) SetActiveByRawURI(uri string) (*models.Server, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	idx := -1
	for i := range sm.data.Servers {
		if sm.data.Servers[i].RawURI == uri {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("сервер не найден по RawURI")
	}
	sm.data.ActiveID = idx
	for i := range sm.data.Servers {
		sm.data.Servers[i].Active = i == idx
	}
	server := sm.data.Servers[idx]
	data, err := json.MarshalIndent(sm.data, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sm.dataDir, 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(sm.filePath(), data, 0600); err != nil {
		return nil, err
	}
	return &server, nil
}

func (sm *SubscriptionManager) GetActiveServer() *models.Server {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if len(sm.data.Servers) == 0 {
		return nil
	}
	id := sm.data.ActiveID
	if id < 0 || id >= len(sm.data.Servers) {
		return nil
	}
	s := sm.data.Servers[id]
	return &s
}

func (sm *SubscriptionManager) SelectNext() (*models.Server, error) {
	sm.mu.RLock()
	count := len(sm.data.Servers)
	current := sm.data.ActiveID
	sm.mu.RUnlock()
	if count == 0 {
		return nil, fmt.Errorf("нет доступных серверов")
	}
	next := (current + 1) % count
	return sm.SetActive(next)
}

func (sm *SubscriptionManager) downloadAndParse(rawURL string) ([]models.Server, error) {
	body, err := downloadSubscription(rawURL, nil)
	if err != nil {
		return nil, err
	}
	if servers, parseErr := ParseSubscription(string(body)); parseErr == nil && !isUnsupportedPlaceholder(servers) {
		return servers, nil
	}
	if servers, parseErr := ParseXraySubscription(string(body)); parseErr == nil && !isUnsupportedPlaceholder(servers) {
		return servers, nil
	}

	hwidBytes, err := os.ReadFile(sm.hwidPath())
	if err != nil {
		return nil, fmt.Errorf("подписка требует совместимый клиент, а HWID не найден в %s: %w", sm.hwidPath(), err)
	}
	hwid := strings.TrimSpace(string(hwidBytes))
	if hwid == "" {
		return nil, fmt.Errorf("HWID пуст в %s", sm.hwidPath())
	}
	headers := map[string]string{
		"User-Agent":     "Happ/3.26.1",
		"x-hwid":         hwid,
		"x-device-os":    "Linux",
		"x-ver-os":       "KeeneticOS",
		"x-device-model": "Netcraze Viva NC-1913",
	}
	body, err = downloadSubscription(rawURL, headers)
	if err != nil {
		return nil, err
	}
	if servers, parseErr := ParseXraySubscription(string(body)); parseErr == nil && !isUnsupportedPlaceholder(servers) {
		return servers, nil
	}
	if servers, parseErr := ParseSubscription(string(body)); parseErr == nil && !isUnsupportedPlaceholder(servers) {
		return servers, nil
	}
	return nil, fmt.Errorf("провайдер вернул неподдерживаемую или заглушечную подписку")
}

func downloadSubscription(rawURL string, headers map[string]string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания запроса подписки: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки подписки: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("сервер вернул код %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения ответа: %w", err)
	}
	return body, nil
}

func isUnsupportedPlaceholder(servers []models.Server) bool {
	if len(servers) != 1 {
		return false
	}
	s := servers[0]
	name := strings.ToLower(strings.ReplaceAll(s.Name, "%20", " "))
	return strings.Contains(name, "app not supported") || (s.Address == "0.0.0.0" && s.Port == 1)
}
