package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"xkeen-panel/internal/auth"
	"xkeen-panel/internal/geoip"
	"xkeen-panel/internal/models"
	"xkeen-panel/internal/monitor"
	"xkeen-panel/internal/server"
	"xkeen-panel/internal/sse"
	"xkeen-panel/internal/xkeen"

	"gopkg.in/yaml.v3"
)

func main() {
	configPath := flag.String("config", "config.yaml", "путь к конфигурационному файлу")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Ошибка загрузки конфига: %v", err)
	}

	userManager := auth.NewUserManager(cfg.DataDir)
	if err := userManager.Load(); err != nil {
		log.Fatalf("Ошибка загрузки пользователя: %v", err)
	}

	subManager := xkeen.NewSubscriptionManager(cfg.DataDir)
	if err := subManager.Load(); err != nil {
		log.Printf("Предупреждение: ошибка загрузки подписки: %v", err)
	}

	detector := xkeen.NewDetector("", cfg.XKeenPath, cfg.InitScript,
		cfg.XrayConfigDir, cfg.RoutingFile, cfg.MihomoConfig, cfg.XkeenJSON)
	rt := detector.Runtime()
	if !rt.Installed {
		log.Printf("XKeen не найден (%s) — управление ядром недоступно", rt.InitScript)
	} else {
		log.Printf("XKeen %s (поколение %d), ядро %s, режим %s", rt.Version, rt.Generation, rt.Core, rt.Mode)
	}

	poolStore := xkeen.NewPoolStore(cfg.DataDir)
	if err := poolStore.Load(); err != nil {
		log.Printf("Предупреждение: не удалось загрузить состояние пула: %v", err)
	}

	if migrated, err := xkeen.EnsureAPIConfig(poolStore.Get(), cfg.XrayAPIAddr); err != nil {
		log.Printf("Не удалось обновить api-блок Xray: %v", err)
	} else if migrated {
		log.Printf("api-блок Xray приведён к текущей форме — перезапускаю ядро")
		xkeen.Restart(rt.Dispatcher)
	}

	watchdog := monitor.NewWatchdog(cfg, subManager, detector)
	eventBus := sse.NewEventBus()
	watchdog.SetEventBus(eventBus)
	watchdog.SetPoolStore(poolStore)
	xkeen.Log = watchdog.Log

	var geoMatcher *geoip.Matcher
	if geoPath := geoip.FindDat(cfg.GeoIPPath); geoPath == "" {
		log.Printf("GeoIP: geoip.dat не найден (%s) — гео-фильтр по IP отключён, используется определение по имени", cfg.GeoIPPath)
	} else if matcher, err := geoip.Load(geoPath, cfg.AutoSwitchAvoidCountries); err != nil {
		log.Printf("GeoIP: ошибка загрузки %s: %v — гео-фильтр по IP отключён", geoPath, err)
	} else {
		geoMatcher = matcher
		watchdog.SetGeoIP(matcher)
		log.Printf("GeoIP: загружен %s (избегаемые страны: %v)", geoPath, cfg.AutoSwitchAvoidCountries)
	}

	if cfg.WatchdogAutoStart && len(subManager.GetServers()) > 0 {
		watchdog.SetActive(true)
		log.Printf("Watchdog включён автоматически (watchdog_auto_start)")
	}

	xkeen.OnRestartStateChange = func(restarting bool) {
		eventBus.Publish(sse.Event{
			Type: "restart",
			Data: map[string]bool{"restarting": restarting},
		})
		eventBus.Publish(sse.Event{
			Type: "status",
			Data: watchdog.GetStatus(),
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go watchdog.Start(ctx)

	if cfg.SubscriptionRefreshInterval > 0 {
		go runSubscriptionRefresh(ctx, cfg, subManager, watchdog, detector, poolStore, geoMatcher, eventBus)
	}

	var frontendFS fs.FS
	distFS, err := fs.Sub(frontendDist, "frontend/dist")
	if err != nil {
		log.Printf("Предупреждение: встроенный фронтенд недоступен: %v", err)
	} else {
		frontendFS = distFS
	}

	srv := server.New(cfg, userManager, subManager, watchdog, detector, poolStore, geoMatcher, eventBus, frontendFS)
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: srv.Handler(),
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Получен сигнал завершения, останавливаем сервер...")
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("Ошибка при остановке сервера: %v", err)
		}
	}()

	log.Printf("XKeen Panel v2 запущена на порту %d (xkeen=%s, outbounds=%s)", cfg.Port, cfg.XKeenPath, cfg.OutboundsFile)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Ошибка сервера: %v", err)
	}

	log.Println("Сервер остановлен")
}

// runSubscriptionRefresh refreshes once immediately after panel startup and
// then waits the configured interval between refreshes. A reboot therefore does
// not postpone the first subscription update by the full interval.
func runSubscriptionRefresh(ctx context.Context, cfg *models.Config, sm *xkeen.SubscriptionManager, wd *monitor.Watchdog, det *xkeen.Detector, pool *xkeen.PoolStore, matcher *geoip.Matcher, bus *sse.EventBus) {
	interval := time.Duration(cfg.SubscriptionRefreshInterval) * time.Second
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if !refreshSubscriptionOnce(ctx, cfg, sm, wd, det, pool, matcher, bus) {
				return
			}
			timer.Reset(interval)
		}
	}
}

func refreshSubscriptionOnce(ctx context.Context, cfg *models.Config, sm *xkeen.SubscriptionManager, wd *monitor.Watchdog, det *xkeen.Detector, pool *xkeen.PoolStore, matcher *geoip.Matcher, bus *sse.EventBus) bool {
	prevURI := ""
	if a := sm.GetActiveServer(); a != nil {
		prevURI = a.RawURI
	}

	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if _, err = sm.Refresh(); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(30 * time.Second):
		}
	}
	if err != nil {
		wd.Log("[AUTO-UPDATE] Подписка не обновилась: %v", err)
		return true
	}

	active := sm.GetActiveServer()
	newURI := ""
	if active != nil {
		newURI = active.RawURI
	}

	rt := det.Runtime()

	if top := det.Topology(); top.Mode == xkeen.TopologyPool {
		state := pool.Get()
		state.BalancerTag = top.BalancerTag
		if len(top.Selectors) > 0 {
			state.Selector = top.Selectors[0]
		}

		res, err := xkeen.RefreshPool(rt, cfg.OutboundsFile, cfg.XrayAPIAddr, sm.GetServers(), state,
			xkeen.PoolSelectionFromConfig(cfg, matcher))
		switch {
		case err != nil:
			wd.Log("[AUTO-UPDATE] Пул не синхронизирован: %v", err)
		case res.Changed:
			det.InvalidateTopology()
			wd.Log("[AUTO-UPDATE] Пул обновлён: +%d, -%d, заменено %d%s", len(res.Added), len(res.Removed), len(res.Replaced), liveSuffix(res))
		}
	} else if active != nil && newURI != prevURI {
		if target := wd.AllowedActiveOrBest(); target != nil {
			if err := xkeen.ApplyServer(rt, cfg.OutboundsFile, target); err != nil {
				log.Printf("[AUTO-UPDATE] Ошибка конфига: %v", err)
			} else {
				xkeen.Restart(rt.Dispatcher)
				log.Printf("[AUTO-UPDATE] Активный сервер заменён на %s, ядро перезапущено", target.Name)
			}
		}
	}

	bus.Publish(sse.Event{Type: "subscription", Data: map[string]bool{"updated": true}})
	wd.Log("[AUTO-UPDATE] Подписка обновлена (%d серверов)", len(sm.GetServers()))
	return true
}

func liveSuffix(res xkeen.SyncResult) string {
	if res.Live {
		return " (без перезапуска)"
	}
	if res.Restarted {
		return " (с перезапуском ядра)"
	}
	return ""
}

func loadConfig(path string) (*models.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &models.Config{
		Port:          3000,
		DataDir:       "data",
		XKeenPath:     "/opt/sbin/xkeen",
		OutboundsFile: "/opt/etc/xray/configs/04_outbounds.json",
		XrayAPIAddr:   "127.0.0.1:10085",
		CheckInterval: 120,
		CheckURL:      "https://www.google.com",
		MaxFails:      3,
		LogFile:       "xkeen-panel.log",

		ProbeTimeoutMs:     2000,
		ProbeConcurrency:   20,
		LatencyAutoSwitch:  true,
		LatencyThresholdMs: 1000,
		LatencySwitchCount: 3,
		BlacklistTTLSec:    300,
		WatchdogAutoStart:  true,

		SubscriptionRefreshInterval: 1800,

		PoolMaxNodes:             xkeen.DefaultPoolMaxNodes,
		HealthCheckURLs:          monitor.DefaultHealthURLs,
		HealthCheckEvery:         5,
		HealthFailThreshold:      2,
		HealthQuorum:             2,
		GeoIPPath:                "/opt/etc/xray/dat/geoip_v2fly.dat",
		AutoSwitchAvoidCountries: []string{"RU", "BY"},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
