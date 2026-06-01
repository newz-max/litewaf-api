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

规则字段：`name`、`type`、`target`、`action`、`expression`、`score`、`enabled`、`module`、`category`、`attack_type`、`group`、`priority`。

支持类型：`sqli`、`xss`、`rce`、`path-traversal`、`cc`、`bot`、`custom`。

支持动作：`pass`、`block`、`log-only`。

托管攻击防护规则使用 `module=attack-protection`、`category=managed`，`attack_type` 支持 `sqli`、`xss`、`rce`、`path-traversal`。普通高级规则仍可通过规则 API 维护表达式；攻击防护模块只暴露托管规则组的启停、观察/阻断动作和优先级。

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

发布配置会保留旧 `rate_limits` 和 `access_lists` 字段，并同步输出 CC 防护、访问控制、上传防护、Bot / 人机验证和动态防护子集到 `protection_rules`；托管攻击防护规则继续位于站点 `rules` 数组中，同时带有网关可识别的 `module=attack-protection`、`category=managed`、`attack_type`、`group` 和 `priority` 元数据：

```json
{
  "rate_limits": [],
  "protection_rules": [
    {
      "module": "cc-protection",
      "category": "rate-limit",
      "match": {
        "path": "/api/login",
        "path_match": "exact",
        "methods": ["POST"]
      },
      "limit": {
        "counter": "client_ip",
        "threshold": 10,
        "window_sec": 60,
        "ban_duration_sec": 600
      },
      "action": {
        "type": "ban"
      }
    },
    {
      "module": "access-control",
      "category": "access-control",
      "priority": 100,
      "match": {
        "target": "path",
        "path": "/admin",
        "path_match": "prefix",
        "methods": []
      },
      "action": {
        "type": "block"
      }
    },
    {
      "module": "upload-protection",
      "category": "upload",
      "priority": 100,
      "match": {
        "target": "upload",
        "path": "/upload",
        "path_match": "prefix",
        "methods": ["POST"]
      },
      "upload": {
        "extensions": ["php", "jsp"],
        "max_bytes": 10485760
      },
      "action": {
        "type": "block"
      }
    },
    {
      "module": "bot-protection",
      "category": "challenge",
      "priority": 80,
      "match": {
        "target": "path",
        "path": "/admin",
        "path_match": "prefix",
        "methods": []
      },
      "challenge": {
        "mode": "js-challenge",
        "verify_ttl_sec": 300,
        "failure_action": "block"
      },
      "action": {
        "type": "block"
      }
    },
    {
      "module": "dynamic-protection",
      "category": "dynamic-token",
      "priority": 80,
      "match": {
        "target": "path",
        "path": "/admin",
        "path_match": "prefix",
        "methods": []
      },
      "dynamic": {
        "mode": "dynamic-token",
        "token_ttl_sec": 300,
        "token_placement": "cookie",
        "failure_action": "block"
      },
      "action": {
        "type": "block"
      }
    }
  ]
}
```

发布预览的 `summary.cc_protection` 包含 CC 规则总数、启用数量和高风险配置提示。`summary.attack_protection` 包含攻击防护组数量、启用数量、观察数量、阻断数量和受影响攻击类型。`summary.access_control` 包含访问控制规则总数、启用数量、允许/观察/阻断数量和宽泛允许类风险提示。`summary.upload_protection` 包含上传防护规则总数、启用数量、扩展名规则数、大小规则数、观察/阻断数量和高风险上传限制提示。`summary.bot_protection` 包含 Bot 规则总数、启用数量、JS challenge 数量、阻断数量、观察数量和宽泛 challenge 提示。`summary.dynamic_protection` 包含动态防护规则总数、启用数量、动态令牌数量、页面动态化数量、等候室数量、阻断数量、观察数量、等候室动作数量和宽泛路径提示。

## 黑白名单

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/access-lists` | 读 | 查询名单 |
| POST | `/api/v1/access-lists` | 写 | 创建名单 |
| GET | `/api/v1/access-lists/{id}` | 读 | 查询名单 |
| PUT | `/api/v1/access-lists/{id}` | 写 | 更新名单 |
| DELETE | `/api/v1/access-lists/{id}` | 写 | 删除名单 |

支持目标：`ip`、`cidr`、`uri`、`ua`。支持类型：`blacklist`、`whitelist`。

## 访问控制

访问控制接口复用现有黑白名单存储，对外以 `module=access-control`、`category=access-control` 的防护规则模型呈现。第一阶段覆盖 IP/CIDR、路径、Header 和 Host 条件，支持 `allow`、`log-only` 和 `block` 动作；旧 `/api/v1/access-lists` 接口和发布字段继续保留用于兼容。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/access-control/rules` | 读 | 查询访问控制规则 |
| POST | `/api/v1/access-control/rules` | 写 | 创建访问控制规则 |
| GET | `/api/v1/access-control/rules/{id}` | 读 | 查询访问控制规则 |
| PUT | `/api/v1/access-control/rules/{id}` | 写 | 更新访问控制规则 |
| DELETE | `/api/v1/access-control/rules/{id}` | 写 | 删除访问控制规则 |

列表支持过滤：

- `site_id`：站点 ID。
- `enabled`：`true` 或 `false`。

请求示例：

```json
{
  "name": "管理后台路径阻断",
  "site_id": 1,
  "enabled": true,
  "priority": 100,
  "match": {
    "target": "path",
    "path": "/admin",
    "path_match": "prefix",
    "methods": []
  },
  "action": {
    "type": "block"
  }
}
```

支持字段：

- `module` 固定为 `access-control`，`category` 固定为 `access-control`；创建和更新时可省略，API 会填充默认值。
- `match.target` 支持 `ip`、`cidr`、`path`、`header`、`host`。
- `match.value` 用于 IP、CIDR 和 Header 值；`match.path` 用于路径条件；`match.host` 用于 Host 条件。
- `match.path` 必须以 `/` 开头，`match.path_match` 支持 `exact`、`prefix`；prefix 匹配按路径段边界处理，`/admin` 不匹配 `/admin2`。
- `match.header_name` 为 Header 条件必填，Header `operator` 支持 `exact`、`contains`。
- Host `operator` 支持 `exact`、`suffix`。
- `match.methods` 支持 `GET`、`POST`、`PUT`、`PATCH`、`DELETE`、`HEAD`、`OPTIONS`，空数组表示全部方法。
- `action.type` 支持 `allow`、`log-only`、`block`。
- `priority` 为正整数，用于发布配置和网关排序。

管理员可以创建、更新和删除访问控制规则；readonly 和 auditor 用户只能读取。写操作会记录 `resource_type=access_control_rule` 的审计日志。

## 上传防护

上传防护接口使用独立的上传防护规则存储，对外以 `module=upload-protection`、`category=upload` 的防护规则模型呈现。当前阶段覆盖上传路径、HTTP 方法、危险扩展名和上传大小限制，支持 `log-only` 和 `block` 动作；策略级高级上传检测字段继续保留用于兼容。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/upload-protection/rules` | 读 | 查询上传防护规则 |
| POST | `/api/v1/upload-protection/rules` | 写 | 创建上传防护规则 |
| GET | `/api/v1/upload-protection/rules/{id}` | 读 | 查询上传防护规则 |
| PUT | `/api/v1/upload-protection/rules/{id}` | 写 | 更新上传防护规则 |
| DELETE | `/api/v1/upload-protection/rules/{id}` | 写 | 删除上传防护规则 |

列表支持过滤：

- `site_id`：站点 ID。
- `enabled`：`true` 或 `false`。

请求示例：

```json
{
  "name": "危险脚本上传阻断",
  "site_id": 1,
  "enabled": true,
  "priority": 100,
  "match": {
    "path": "/upload",
    "path_match": "prefix",
    "methods": ["POST"]
  },
  "upload": {
    "extensions": ["php", "jsp", "asp"],
    "max_bytes": 10485760
  },
  "action": {
    "type": "block"
  }
}
```

支持字段：

- `module` 固定为 `upload-protection`，`category` 固定为 `upload`；创建和更新时可省略，API 会填充默认值。
- `match.path` 必须以 `/` 开头。
- `match.path_match` 支持 `exact`、`prefix`；prefix 匹配按路径段边界处理，`/upload` 不匹配 `/upload2`。
- `match.methods` 支持 `GET`、`POST`、`PUT`、`PATCH`、`DELETE`、`HEAD`、`OPTIONS`，空数组表示全部方法。
- `upload.extensions` 会去掉开头的点并转为小写，不允许路径分隔符或 `..`。
- `upload.max_bytes` 为 `0` 时表示不启用大小限制；规则必须至少配置扩展名或大小限制之一。
- `action.type` 支持 `log-only`、`block`。
- `priority` 为正整数，用于发布配置和网关排序。

管理员可以创建、更新和删除上传防护规则；readonly 和 auditor 用户只能读取。写操作会记录 `resource_type=upload_protection_rule` 的审计日志。

## Bot / 人机验证

Bot / 人机验证接口使用独立规则存储，对外以 `module=bot-protection`、`category=challenge` 的防护规则模型呈现。当前阶段只支持本地 JavaScript challenge，不包含第三方 captcha、行为评分、设备指纹、动态令牌或等候室。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/bot-protection/rules` | 读 | 查询 Bot 验证规则 |
| POST | `/api/v1/bot-protection/rules` | 写 | 创建 Bot 验证规则 |
| GET | `/api/v1/bot-protection/rules/{id}` | 读 | 查询 Bot 验证规则 |
| PUT | `/api/v1/bot-protection/rules/{id}` | 写 | 更新 Bot 验证规则 |
| DELETE | `/api/v1/bot-protection/rules/{id}` | 写 | 删除 Bot 验证规则 |

列表支持过滤：

- `site_id`：站点 ID。
- `enabled`：`true` 或 `false`。

请求示例：

```json
{
  "name": "后台路径 JS Challenge",
  "site_id": 1,
  "enabled": true,
  "priority": 80,
  "match": {
    "path": "/admin",
    "path_match": "prefix",
    "methods": []
  },
  "challenge": {
    "mode": "js-challenge",
    "verify_ttl_sec": 300,
    "failure_action": "block"
  }
}
```

响应中的规则会补齐 `module=bot-protection`、`category=challenge`、`action.type` 和时间字段。

支持字段：

- `module` 固定为 `bot-protection`，`category` 固定为 `challenge`；创建和更新时可省略，API 会填充默认值。
- `match.path` 必须以 `/` 开头。
- `match.path_match` 支持 `exact`、`prefix`；prefix 匹配按路径段边界处理，`/admin` 不匹配 `/admin2`。
- `match.methods` 支持 `GET`、`POST`、`PUT`、`PATCH`、`DELETE`、`HEAD`、`OPTIONS`，空数组表示全部方法。
- `challenge.mode` 当前仅支持 `js-challenge`。
- `challenge.verify_ttl_sec` 必须大于 `0` 且不超过 `86400`。
- `challenge.failure_action` 支持 `block`、`log-only`。
- `action.type` 可省略；传入时必须与 `challenge.failure_action` 一致。
- `priority` 不能为负数，发布和网关按较小值优先执行。

管理员可以创建、更新和删除 Bot 验证规则；readonly 和 auditor 用户只能读取。写操作会记录 `resource_type=bot_protection_rule` 的审计日志。

## 动态防护 / 等候室

动态防护接口使用独立规则存储，对外以 `module=dynamic-protection` 的防护规则模型呈现。当前阶段支持 `dynamic-token`、`page-mutation` 和 `waiting-room` 三类规则，不包含 captcha、行为评分、设备指纹、完整 JavaScript 混淆或分布式全局队列。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/dynamic-protection/rules` | 读 | 查询动态防护规则 |
| POST | `/api/v1/dynamic-protection/rules` | 写 | 创建动态防护规则 |
| GET | `/api/v1/dynamic-protection/rules/{id}` | 读 | 查询动态防护规则 |
| PUT | `/api/v1/dynamic-protection/rules/{id}` | 写 | 更新动态防护规则 |
| DELETE | `/api/v1/dynamic-protection/rules/{id}` | 写 | 删除动态防护规则 |

列表支持过滤：

- `site_id`：站点 ID。
- `enabled`：`true` 或 `false`。
- `category`：`dynamic-token`、`page-mutation`、`waiting-room`。

动态令牌请求示例：

```json
{
  "name": "后台动态令牌",
  "site_id": 1,
  "enabled": true,
  "priority": 80,
  "category": "dynamic-token",
  "match": {
    "path": "/admin",
    "path_match": "prefix",
    "methods": []
  },
  "dynamic": {
    "mode": "dynamic-token",
    "token_ttl_sec": 300,
    "token_placement": "cookie",
    "failure_action": "block"
  }
}
```

页面动态化请求示例：

```json
{
  "name": "HTML 页面标记注入",
  "site_id": 1,
  "enabled": true,
  "priority": 90,
  "category": "page-mutation",
  "match": {
    "path": "/",
    "path_match": "prefix",
    "methods": ["GET"]
  },
  "dynamic": {
    "mode": "page-mutation",
    "mutation_marker": "body-end",
    "mutation_max_bytes": 262144
  }
}
```

等候室请求示例：

```json
{
  "name": "抢购路径等候室",
  "site_id": 1,
  "enabled": true,
  "priority": 70,
  "category": "waiting-room",
  "match": {
    "path": "/checkout",
    "path_match": "prefix",
    "methods": []
  },
  "dynamic": {
    "mode": "waiting-room",
    "queue_capacity": 100,
    "admission_ttl_sec": 300,
    "retry_interval_sec": 5,
    "overflow_action": "waiting-room"
  }
}
```

支持字段：

- `module` 固定为 `dynamic-protection`；创建和更新时可省略，API 会填充默认值。
- `category` 支持 `dynamic-token`、`page-mutation`、`waiting-room`。
- `match.path` 必须以 `/` 开头。
- `match.path_match` 支持 `exact`、`prefix`；prefix 匹配按路径段边界处理，`/admin` 不匹配 `/admin2`。
- `match.methods` 支持 `GET`、`POST`、`PUT`、`PATCH`、`DELETE`、`HEAD`、`OPTIONS`，空数组表示全部方法。
- `dynamic.token_ttl_sec` 必须大于 `0` 且不超过 `86400`。
- `dynamic.token_placement` 支持 `cookie`、`header`、`query`；网关不会记录原始 token。
- `dynamic.failure_action` 支持 `block`、`log-only`。
- `dynamic.mutation_marker` 支持 `head-end`、`body-end`。
- `dynamic.mutation_max_bytes` 必须大于 `0` 且不超过 `1048576`。
- `dynamic.queue_capacity` 必须大于 `0` 且不超过 `100000`。
- `dynamic.admission_ttl_sec` 和 `dynamic.retry_interval_sec` 必须大于 `0` 且不超过 `86400`。
- `dynamic.overflow_action` 支持 `waiting-room`、`block`、`log-only`。
- `action.type` 可省略；动态令牌规则必须与 `failure_action` 一致，等候室规则必须与 `overflow_action` 一致，页面动态化固定为 `log-only`。
- `priority` 不能为负数，发布和网关按较小值优先执行。

管理员可以创建、更新和删除动态防护规则；readonly 和 auditor 用户只能读取。写操作会记录 `resource_type=dynamic_protection_rule` 的审计日志。

## 限流

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/rate-limits` | 读 | 查询限流规则 |
| POST | `/api/v1/rate-limits` | 写 | 创建限流规则 |
| GET | `/api/v1/rate-limits/{id}` | 读 | 查询限流规则 |
| PUT | `/api/v1/rate-limits/{id}` | 写 | 更新限流规则 |
| DELETE | `/api/v1/rate-limits/{id}` | 写 | 删除限流规则 |

限流支持 IP、URI、站点维度，重复违规可触发临时封禁。

## CC 防护

CC 防护接口复用现有限流存储，对外以 `module=cc-protection`、`category=rate-limit` 的防护规则模型呈现。第一阶段只覆盖 URL 访问频率限制、登录防爆破和 API 调用限流，不包含攻击防护、上传防护、Bot、人机验证或动态防护。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/cc-protection/rules` | 读 | 查询 CC 防护规则 |
| POST | `/api/v1/cc-protection/rules` | 写 | 创建 CC 防护规则 |
| GET | `/api/v1/cc-protection/rules/{id}` | 读 | 查询 CC 防护规则 |
| PUT | `/api/v1/cc-protection/rules/{id}` | 写 | 更新 CC 防护规则 |
| DELETE | `/api/v1/cc-protection/rules/{id}` | 写 | 删除 CC 防护规则 |

列表支持过滤：

- `site_id`：站点 ID。
- `enabled`：`true` 或 `false`。

请求示例：

```json
{
  "name": "登录接口防爆破",
  "site_id": 1,
  "enabled": true,
  "match": {
    "path": "/api/login",
    "path_match": "exact",
    "methods": ["POST"]
  },
  "limit": {
    "counter": "client_ip",
    "threshold": 10,
    "window_sec": 60,
    "ban_duration_sec": 600
  },
  "action": {
    "type": "ban"
  }
}
```

支持字段：

- `match.path` 必须以 `/` 开头。
- `match.path_match` 支持 `exact`、`prefix`。
- `match.methods` 支持 `GET`、`POST`、`PUT`、`PATCH`、`DELETE`、`HEAD`、`OPTIONS`，空数组表示全部方法。
- `limit.counter` 支持 `client_ip`、`client_ip_path`、`global`。
- `action.type` 支持 `log-only`、`block`、`rate-limit`、`ban`。

## 攻击防护

攻击防护接口聚合现有托管规则，对外以 `module=attack-protection`、`category=managed` 的规则组模型呈现。当前阶段只覆盖 SQL 注入、XSS、RCE 和路径穿越，不包含访问控制、上传防护、Bot、人机验证或动态防护。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/attack-protection/groups` | 读 | 查询攻击防护托管规则组 |
| PUT | `/api/v1/attack-protection/groups/{attack_type}` | 写 | 更新攻击防护组启停、动作和优先级 |

`attack_type` 支持：

- `sqli`
- `xss`
- `rce`
- `path-traversal`

请求示例：

```json
{
  "enabled": true,
  "action": "block",
  "priority": 100
}
```

支持字段：

- `enabled`：控制该攻击类型下托管规则组是否启用。
- `action`：支持 `log-only`、`block`，不支持 `pass` 或 challenge 类动作。
- `priority`：正整数，用于发布配置和后台排序。

管理员可以写入攻击防护组；readonly 和 auditor 用户只能读取。写操作会记录 `resource_type=attack_protection_group` 的审计日志。

## 高级规则生态

高级规则生态接口用于本地规则包预览、导入、来源追踪和规则测试。第一版只支持操作员主动提交本地 JSON 规则包，不实现远程市场、付费规则源或自动更新。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/rule-packages` | 读 | 查询已导入规则来源包 |
| GET | `/api/v1/rule-packages/{id}` | 读 | 查询规则包元数据 |
| POST | `/api/v1/rule-packages/preview` | 写 | 预览规则包，不激活规则 |
| POST | `/api/v1/rule-packages/import` | 写 | 导入规则包，按 `package_id + package_rule_id` 确定性新增或更新规则 |
| DELETE | `/api/v1/rule-packages/{id}` | 写 | 删除该来源包导入的规则 |
| POST | `/api/v1/rules/test` | 写 | 使用受限样例测试规则表达式 |

规则包预览请求：

```json
{
  "package": {
    "id": "community-baseline",
    "name": "Community baseline",
    "version": "v1",
    "author": "LiteWaf Community",
    "license": "MIT",
    "compatibility": "litewaf-rule-package-v1",
    "defaults": {
      "enabled": false,
      "review_status": "pending-review"
    },
    "rules": [
      {
        "id": "xss-query",
        "name": "Community XSS",
        "type": "xss",
        "target": "args",
        "action": "block",
        "expression": "(?i)<script",
        "score": 80
      }
    ]
  }
}
```

`package` 为空对象时，API 使用内置默认规则包进行预览或导入。签名状态包括 `verified`、`unsigned`、`invalid`、`untrusted-key`；第一版将签名作为来源状态和发布预览警告，不强制拒绝未签名本地包。

规则测试请求：

```json
{
  "rule_id": 1,
  "sample": {
    "method": "GET",
    "path": "/search",
    "query": {
      "q": "<script>alert(1)</script>"
    },
    "headers": {
      "x-demo": "value"
    },
    "body": "",
    "upload_filename": "",
    "upload_mime": "",
    "upload_size": 0
  }
}
```

规则测试不会保存完整请求体、Authorization、Cookie 或上传文件内容；样例字段有大小和敏感头限制。成功测试会更新规则的 `last_test_status`，发布预览会提示未测试的启用阻断型导入规则。

## 日志和观测

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/access-logs` | 读 | 查询访问日志 |
| GET | `/api/v1/attack-logs` | 读 | 查询 WAF 事件 |
| GET | `/api/v1/observability/summary` | 读 | 查询汇总指标 |
| POST | `/api/v1/ingest/access-logs` | 网关令牌 | 接收访问日志 |
| POST | `/api/v1/ingest/waf-events` | 网关令牌 | 接收 WAF 事件 |

攻击日志支持 `module`、`attack_type` 和 `action` 过滤。例如：

```text
GET /api/v1/attack-logs?module=attack-protection&attack_type=sqli
GET /api/v1/attack-logs?module=access-control&action=block
GET /api/v1/attack-logs?module=upload-protection&action=block
GET /api/v1/attack-logs?module=bot-protection&challenge_result=failed
GET /api/v1/attack-logs?module=dynamic-protection&dynamic_result=token-failed
```

攻击防护事件字段包括 `module`、`category`、`attack_type`、`group_name`、`rule_name`、`rule_id`、`target`、`action`、`score`、`summary` 和 `disposition`。观测汇总中的 `attack_protection` 按 `attack_type|action|disposition` 维度统计。

访问控制事件字段包括 `module=access-control`、`category=access-control`、`rule_name`、`rule_id`、`target`、`action` 和 `disposition`。观测汇总中的 `access_control` 按 `action|disposition` 维度统计，例如 `block|blocked`、`log-only|observed` 或 `allow|allowed`。

上传防护事件字段包括 `module=upload-protection`、`category=upload`、`rule_name`、`rule_id`、`target`、`action`、`disposition`、`threshold` 和 `upload_metadata`。观测汇总中的 `upload_protection` 按 `action|disposition` 维度统计，例如 `block|blocked` 或 `log-only|observed`。

Bot 验证事件字段包括 `module=bot-protection`、`category=challenge`、`rule_name`、`rule_id`、`target`、`action`、`disposition`、`challenge_mode` 和 `challenge_result`。`challenge_result` 支持 `issued`、`passed`、`failed`；观测汇总中的 `bot_protection` 按 `challenge_result|action|disposition` 维度统计，例如 `issued|block|blocked`、`passed|pass|proxied` 或 `failed|block|blocked`。

动态防护事件字段包括 `module=dynamic-protection`、`category`、`rule_name`、`rule_id`、`target`、`action`、`disposition` 和 `advanced_target`。`advanced_target` 承载动态结果，可通过 `dynamic_result` 查询参数过滤，常见值包括 `token-issued`、`token-passed`、`token-failed`、`mutation-applied`、`mutation-skipped`、`queue-admitted`、`queue-queued`、`queue-blocked` 和 `queue-observed`。观测汇总中的 `dynamic_protection` 按 `category|result|action|disposition` 维度统计。

## 审计和系统

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/audit-logs` | 审计/管理员 | 查询审计日志 |
| GET | `/api/v1/version` | 读 | 查询版本 |
| GET | `/metrics` | 环境变量控制 | Prometheus 文本指标 |
