package app

import (
	"litewaf-api/internal/config"
	"litewaf-api/internal/geoip"
	"litewaf-api/internal/store"
)

var Version = "0.5.1"

type App struct {
	Config        config.Config
	Store         store.Store
	GeoIPResolver geoip.Resolver
}

func New(cfg config.Config, dataStore store.Store) *App {
	return &App{
		Config:        cfg,
		Store:         dataStore,
		GeoIPResolver: geoip.NewResolver(geoip.Options{DatabasePath: cfg.GeoIPDatabasePath, ChinaDatabasePath: cfg.GeoIPChinaDatabasePath, CacheSize: cfg.GeoIPCacheSize}),
	}
}
