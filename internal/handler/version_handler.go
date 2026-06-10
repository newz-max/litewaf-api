package handler

import (
	"net/http"

	"github.com/zeromicro/go-zero/rest/httpx"

	"litewaf-api/internal/logic/system"
	"litewaf-api/internal/svc"
)

func VersionHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l := system.NewVersionLogic(r.Context(), svcCtx)
		httpx.OkJsonCtx(r.Context(), w, l.Version())
	}
}
