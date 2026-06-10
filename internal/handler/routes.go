package handler

import (
	"net/http"

	"github.com/zeromicro/go-zero/rest"

	"litewaf-api/internal/svc"
)

func RegisterHandlers(server *rest.Server, serverCtx *svc.ServiceContext) {
	server.AddRoutes([]rest.Route{
		{
			Method:  http.MethodGet,
			Path:    "/healthz",
			Handler: HealthzHandler(serverCtx),
		},
		{
			Method:  http.MethodGet,
			Path:    "/api/v1/version",
			Handler: VersionHandler(serverCtx),
		},
	})
}
