# LiteWaf

LiteWaf 是一个以开源、轻便、快速部署为目标的 OpenResty WAF 项目。数据面使用 OpenResty + LuaJIT，控制面使用 Go 标准库，后台管理使用 Vue 3 + TypeScript + Vite + Naive UI，默认推荐 Debian 12 minimal + Docker Compose 部署。

## 当前能力

- 站点、规则、策略、发布记录管理。
- 登录、Bearer Token 鉴权、角色权限和审计日志。
- 黑白名单、限流、发布预览和历史版本回滚。
- OpenResty 网关按发布配置执行代理、名单、限流、规则匹配、评分阈值、请求体和上传元数据检测。
- 访问日志、WAF 事件、观测汇总和基础 Prometheus 指标。
- 生产 Compose、环境变量模板、健康检查、备份、恢复、升级和回滚脚本。
- 版本化默认规则集和本地验证样例。

## 快速开始

```bash
cd deploy
docker compose up -d --build
```

默认入口：

- Dashboard: `http://localhost:18080`
- Gateway: `http://localhost:18081`
- API: Dashboard 反代 `/api/`，容器内地址为 `waf-api:8080`

更完整的首次验证流程见 [快速开始](doc/快速开始.md)。

## 目录结构

```text
./                   当前仓库，Go 控制面 API
deploy/              Compose、生产脚本和验证 upstream 配置
doc/                 架构、部署、验证和使用文档
rules/               默认规则集
examples/            本地验证样例
../../openspec/       工作区级规格和变更工作流
litewaf-dashboard    配套前端仓库
litewaf-gateway      配套网关仓库
```

## 相关仓库

- 后端与项目文档：[litewaf-api](https://github.com/newz-max/litewaf-api)
- 前端管理台：[litewaf-dashboard](https://github.com/newz-max/litewaf-dashboard)
- OpenResty 数据面网关：[litewaf-gateway](https://github.com/newz-max/litewaf-gateway)

## 文档入口

- [快速开始](doc/快速开始.md)
- [架构说明](doc/架构说明.md)
- [API 文档](doc/API文档.md)
- [规则编写指南](doc/规则编写指南.md)
- [贡献指南](doc/贡献指南.md)
- [规则生态路线](doc/规则生态路线.md)
- [Debian 12 minimal 部署说明](doc/Debian12部署说明.md)
- [MVP 防护闭环验证](doc/MVP防护闭环验证.md)

## 开发命令

后端：

```bash
go test ./...
go run ./cmd/litewaf-api
```

前端源码在配套仓库中维护：

```bash
npm install
npm run build
npm run dev
```

网关源码在配套仓库中维护：

```bash
docker build -t litewaf-gateway .
```

## 规则集

默认规则集位于 [rules/default-rules.json](rules/default-rules.json)，控制面启动时会将这些规则作为真实托管规则写入存储。默认规则用于开箱验证和基础防护，不等同于完整托管规则库，生产环境应结合业务流量调优。

## 许可证

当前仓库尚未补充正式开源许可证文件。发布公开版本前应新增 `LICENSE` 并在贡献指南中同步说明。
