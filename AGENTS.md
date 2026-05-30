# LiteWaf API 协作指南

## 仓库定位

本目录是 LiteWaf 控制面 API 的独立 Git 仓库，负责管理站点、规则、策略、发布、鉴权、审计、黑白名单和限流配置。

仓库边界：

- 当前目录 `codes/litewaf-api` 是实际 Git 仓库。
- 根目录 `D:\Project\web_safe` 不是 Git 仓库。
- 前端改动在 `codes/litewaf-dashboard` 仓库中提交。
- 网关目录 `codes/litewaf-gateway` 当前不是 Git 仓库。

## 技术栈

- Go 1.22。
- HTTP 服务使用 `net/http` 标准库。
- PostgreSQL 驱动使用 `github.com/jackc/pgx/v5/stdlib`。
- 密码哈希使用 `golang.org/x/crypto/bcrypt`。
- 默认运行环境以 Debian 12 和 Docker Compose 为目标。

## 目录职责

```text
cmd/litewaf-api/
  服务启动入口、配置加载、存储初始化、优雅停机。

internal/app/
  应用级依赖容器。

internal/config/
  环境变量配置解析。

internal/model/
  API、存储和发布流程共享的数据模型。

internal/store/
  Store 接口、PostgreSQL 实现、内存实现、schema 初始化。

internal/httpserver/
  路由、handler、中间件、鉴权、响应封装和 HTTP 测试。

internal/auth/
  密码哈希、token 签发和 token 校验。

internal/publish/
  网关配置生成、发布校验、配置文件原子写入。

db/init/
  Docker Compose PostgreSQL 初始化 SQL。
```

## 开发原则

- 保持轻量：除非明确需要，不引入 Gin、Echo、Fiber、ORM 或复杂迁移框架。
- 所有管理 API 继续使用 `/api/v1` 前缀；健康检查保持 `/healthz`。
- `/healthz`、`/api/v1/version`、`/api/v1/auth/login` 可公开访问，其他管理接口需要 Bearer Token。
- 配置必须通过环境变量注入，不写死生产密钥、连接串或默认生产密码。
- `DATABASE_URL` 为空时必须继续支持内存存储，方便本地开发和测试。
- 列表接口无数据时返回成功响应和空数组，不返回 mock 数据。
- 日志输出到 stdout，优先保持 JSON 结构化日志。

## 存储和模型约定

- 新实体先扩展 `internal/model/model.go`。
- 所有持久化能力必须走 `internal/store.Store` 接口。
- 新增 Store 方法时同时补齐：
  - `internal/store/memory.go`
  - `internal/store/postgres.go`
  - `internal/store/schema.go`
  - `db/init/001_mvp_schema.sql`
- 数据库变更优先使用 additive schema，避免破坏已有开发数据。
- PostgreSQL 与内存实现的行为要尽量一致，尤其是空列表、NotFound、ID、时间字段。

## HTTP 和鉴权约定

- 路由集中维护在 `internal/httpserver/routes.go`。
- Handler 保持薄层：解析请求、调用 store/publish/auth、返回统一 JSON。
- 已知错误优先转换成明确 HTTP 状态码；未知错误记录日志并返回 500。
- 写操作应调用审计日志，至少包含 actor、role、action、resource type、resource id、result。
- 角色边界：
  - `admin`：读写、发布、回滚、查看审计。
  - `auditor`：读取配置和审计，不允许写入。
  - `readonly`：读取配置，不允许写入或查看审计。

## 发布和网关配置

- 发布前必须调用校验逻辑，避免无效规则或不完整策略写入 active config。
- 网关配置由 `internal/publish` 生成，不在 handler 中拼 JSON。
- 发布输出需要包含站点、规则、黑白名单和限流配置。
- 写配置文件使用原子写入，避免网关读取半写入文件。
- 回滚应基于历史成功发布版本保存的配置 JSON。

## 测试和验证

常用命令：

```bash
go run ./cmd/litewaf-api
go test ./...
docker build -t litewaf-api .
```

测试要求：

- 新增 handler 时补 HTTP 测试，覆盖成功、校验失败、未认证或无权限场景。
- 新增 Store 方法时补内存存储测试；PostgreSQL 行为要跟 schema 和 SQL 保持一致。
- 发布配置变更时补 `internal/publish` 测试，验证生成 payload 和 checksum。
- 提交前至少运行 `go test ./...`。

## Git 约定

- Git commit message 默认使用中文。
- 不提交 `.env`、日志、临时文件、构建产物或本地数据库文件。
- 不回滚用户已有改动，除非用户明确要求。
