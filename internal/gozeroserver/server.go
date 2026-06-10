package gozeroserver

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/zeromicro/go-zero/core/service"
	"github.com/zeromicro/go-zero/rest"

	"litewaf-api/internal/app"
	"litewaf-api/internal/config"
	"litewaf-api/internal/handler"
	"litewaf-api/internal/svc"
)

func New(cfg config.Config, logger *slog.Logger, application *app.App) (*rest.Server, error) {
	server, err := rest.NewServer(restConf(cfg))
	if err != nil {
		return nil, err
	}
	handler.RegisterHandlers(server, svc.NewServiceContext(logger, application))
	return server, nil
}

func restConf(cfg config.Config) rest.RestConf {
	host, port := parseHTTPAddr(cfg.HTTPAddr)
	return rest.RestConf{
		ServiceConf: service.ServiceConf{
			Name: cfg.AppName,
			Mode: zeroMode(cfg.Env),
		},
		Host:    host,
		Port:    port,
		Timeout: 30000,
	}
}

func parseHTTPAddr(addr string) (string, int) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "0.0.0.0", 8080
	}

	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		portText = strings.TrimPrefix(addr, ":")
		host = "0.0.0.0"
	}
	if host == "" {
		host = "0.0.0.0"
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		panic(fmt.Sprintf("invalid HTTP_ADDR for go-zero runtime: %q", addr))
	}
	return host, port
}

func zeroMode(env string) string {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "dev", "development":
		return service.DevMode
	case "test":
		return service.TestMode
	case "rt":
		return service.RtMode
	case "pre", "staging":
		return service.PreMode
	default:
		return service.ProMode
	}
}
