package system

import (
	"context"
	"net/http"
	"time"

	"litewaf-api/internal/svc"
	"litewaf-api/internal/types"
)

type HealthzLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewHealthzLogic(ctx context.Context, svcCtx *svc.ServiceContext) *HealthzLogic {
	return &HealthzLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *HealthzLogic) Healthz() (types.HealthzResp, int) {
	now := time.Now().UTC().Format(time.RFC3339)
	if err := l.svcCtx.Store.Ping(l.ctx); err != nil {
		return types.HealthzResp{
			Status: "degraded",
			Error:  "database unavailable",
			Time:   now,
		}, http.StatusServiceUnavailable
	}

	return types.HealthzResp{
		Status: "ok",
		Time:   now,
	}, http.StatusOK
}
