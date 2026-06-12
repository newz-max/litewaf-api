package system

import (
	"context"

	"litewaf-api/internal/app"
	"litewaf-api/internal/svc"
	"litewaf-api/internal/types"
)

type VersionLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

func NewVersionLogic(ctx context.Context, svcCtx *svc.ServiceContext) *VersionLogic {
	return &VersionLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *VersionLogic) Version() types.VersionResp {
	return types.VersionResp{
		Name:                     l.svcCtx.Config.AppName,
		Version:                  app.Version,
		Env:                      l.svcCtx.Config.Env,
		GatewayClientMaxBodySize: l.svcCtx.Config.NormalizedGatewayClientMaxBodySize(),
	}
}
