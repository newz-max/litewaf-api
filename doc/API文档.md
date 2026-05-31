# LiteWaf API 文档

LiteWaf 管理 API 默认使用 `/api/v1` 前缀。生产环境建议只通过受保护的管理入口访问，不要将 API 和后台直接裸露到公网。

## 通用约定

- 请求和响应格式：JSON。
- 登录外接口需要 `Authorization: Bearer <token>`。
- 网关日志上报接口使用 `X-LiteWaf-Ingestion-Token`。
- 时间字段使用 RFC3339 或数据库返回的时间格式。
- 列表接口在无数据时返回空数组，不返回 mock 数据。

错误响应示例：

```json
{
  "error": "validation failed"
}
```

## 登录

### `POST /api/v1/login`

请求：

```json
{
  "username": "admin",
  "password": "admin123456"
}
```

响应包含访问令牌、角色和用户信息。后续请求添加：

```text
Authorization: Bearer <token>
```

## 站点

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/sites` | 读 | 查询站点 |
| POST | `/api/v1/sites` | 写 | 创建站点 |
| GET | `/api/v1/sites/{id}` | 读 | 查询单个站点 |
| PUT | `/api/v1/sites/{id}` | 写 | 更新站点 |
| DELETE | `/api/v1/sites/{id}` | 写 | 删除站点 |

站点字段：`name`、`host`、`upstream`、`mode`、`enabled`。`mode` 支持 `monitor`、`protect`、`off`。

## 规则

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/rules` | 读 | 查询规则 |
| POST | `/api/v1/rules` | 写 | 创建规则 |
| GET | `/api/v1/rules/{id}` | 读 | 查询单条规则 |
| PUT | `/api/v1/rules/{id}` | 写 | 更新规则 |
| DELETE | `/api/v1/rules/{id}` | 写 | 删除规则 |

规则字段：`name`、`type`、`target`、`action`、`expression`、`score`、`enabled`。

支持类型：`sqli`、`xss`、`rce`、`cc`、`bot`、`custom`。

支持动作：`pass`、`block`、`log-only`。

## 策略

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/policies` | 读 | 查询策略 |
| POST | `/api/v1/policies` | 写 | 创建策略 |
| GET | `/api/v1/policies/{id}` | 读 | 查询单个策略 |
| PUT | `/api/v1/policies/{id}` | 写 | 更新策略 |
| DELETE | `/api/v1/policies/{id}` | 写 | 删除策略 |

策略绑定 `site_ids` 和 `rule_ids`。高级字段包括归一化、Body 检测、上传检测和动态封禁配置。

## 发布

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/releases` | 读 | 查询发布记录 |
| GET | `/api/v1/releases/preview` | 发布 | 预览发布摘要 |
| POST | `/api/v1/releases` | 发布 | 生成新发布版本 |
| POST | `/api/v1/releases/{version}/rollback` | 发布 | 回滚到历史版本 |

发布会生成网关配置并写入 `GATEWAY_CONFIG_PATH`。

## 黑白名单

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/access-lists` | 读 | 查询名单 |
| POST | `/api/v1/access-lists` | 写 | 创建名单 |
| GET | `/api/v1/access-lists/{id}` | 读 | 查询名单 |
| PUT | `/api/v1/access-lists/{id}` | 写 | 更新名单 |
| DELETE | `/api/v1/access-lists/{id}` | 写 | 删除名单 |

支持目标：`ip`、`cidr`、`uri`、`ua`。支持类型：`blacklist`、`whitelist`。

## 限流

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/rate-limits` | 读 | 查询限流规则 |
| POST | `/api/v1/rate-limits` | 写 | 创建限流规则 |
| GET | `/api/v1/rate-limits/{id}` | 读 | 查询限流规则 |
| PUT | `/api/v1/rate-limits/{id}` | 写 | 更新限流规则 |
| DELETE | `/api/v1/rate-limits/{id}` | 写 | 删除限流规则 |

限流支持 IP、URI、站点维度，重复违规可触发临时封禁。

## 日志和观测

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/access-logs` | 读 | 查询访问日志 |
| GET | `/api/v1/attack-logs` | 读 | 查询 WAF 事件 |
| GET | `/api/v1/observability/summary` | 读 | 查询汇总指标 |
| POST | `/api/v1/ingest/access-logs` | 网关令牌 | 接收访问日志 |
| POST | `/api/v1/ingest/waf-events` | 网关令牌 | 接收 WAF 事件 |

## 审计和系统

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/audit-logs` | 审计/管理员 | 查询审计日志 |
| GET | `/api/v1/version` | 读 | 查询版本 |
| GET | `/metrics` | 环境变量控制 | Prometheus 文本指标 |
