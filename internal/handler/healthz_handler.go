package handler

import (
	"net/http"

	"github.com/zeromicro/go-zero/rest/httpx"

	"litewaf-api/internal/logic/system"
	"litewaf-api/internal/svc"
)

func HealthzHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l := system.NewHealthzLogic(r.Context(), svcCtx)
		resp, status := l.Healthz()
		httpx.WriteJsonCtx(r.Context(), w, status, resp)
	}
}
