# LiteWaf API

LiteWaf API 是 LiteWaf 控制面的后端服务模板，负责站点管理、规则管理、策略管理、发布回滚和日志查询等能力。

当前版本使用 Go 标准库 HTTP 服务作为基础模板，方便后续按需引入 Gin、chi、数据库驱动、Redis 客户端和鉴权模块。

## 运行

```bash
go run ./cmd/litewaf-api
```

默认监听：

```text
:8080
```

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| APP_NAME | LiteWaf API | 应用名称 |
| APP_ENV | dev | 运行环境 |
| HTTP_ADDR | :8080 | HTTP 监听地址 |
| LOG_LEVEL | info | 日志级别，支持 debug/info/warn/error |
| DATABASE_URL | 空 | PostgreSQL 连接地址 |
| REDIS_ADDR | 空 | Redis 地址 |

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | /healthz | 健康检查 |
| GET | /api/v1/version | 版本信息 |
| GET | /api/v1/sites | 站点列表 |
| POST | /api/v1/sites | 创建站点，占位 |
| GET | /api/v1/rules | 规则列表 |
| POST | /api/v1/rules | 创建规则，占位 |
| GET | /api/v1/policies | 策略列表 |
| POST | /api/v1/policies | 创建策略，占位 |
| GET | /api/v1/attack-logs | 攻击日志 |
| POST | /api/v1/releases | 发布规则，占位 |

## Docker 构建

```bash
docker build -t litewaf-api .
docker run --rm -p 8080:8080 litewaf-api
```

## 部署环境

项目默认以 Debian 12 作为主要部署系统。后端镜像运行时基于 `debian:12-slim`，便于和生产系统环境保持一致。
