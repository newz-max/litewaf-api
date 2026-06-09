# LiteWaf API 文档

> 语言 / Language: [中文](API文档.md) | [English](en/api.md)

LiteWaf 管理 API 默认使用 `/api/v1` 前缀。生产环境建议只通过受保护的管理入口访问，不要将 API 和后台直接裸露到公网。

## 通用约定

- 请求和响应格式：JSON。
- 登录外接口需要 `Authorization: Bearer <token>`。
- 网关日志上报和网关专用同步接口使用 `Authorization: Bearer <gateway-token>`。
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

## 防护应用

`/api/v1/sites` 已从 active API 中移除。防护入口统一使用防护应用模型维护。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/applications` | 读 | 查询防护应用 |
| POST | `/api/v1/applications` | 写 | 创建防护应用 |
| GET | `/api/v1/applications/{id}` | 读 | 查询单个防护应用 |
| PUT | `/api/v1/applications/{id}` | 写 | 更新防护应用 |
| DELETE | `/api/v1/applications/{id}` | 写 | 删除防护应用 |

应用字段：`name`、`mode`、`enabled`、`description`、`hosts`、`listeners`、`upstreams`。`mode` 支持 `monitor`、`protect`、`off`。

- `hosts[]`：`host`、`is_primary`。
- `listeners[]`：`port`、`protocol`、`certificate_id`、`enabled`，`protocol` 支持 `http`、`https`。
- `upstreams[]`：`name`、`url`、`weight`、`enabled`。

HTTPS 监听启用时必须绑定可用证书。创建、更新、删除或启停防护应用只会修改控制面数据；必须调用 `POST /api/v1/releases` 发布新版本后，网关才会按新的应用入口、端口、协议和上游执行。

## 证书

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/certificates` | 读 | 查询证书安全元数据 |
| POST | `/api/v1/certificates` | 写 | 上传证书和私钥 |
| POST | `/api/v1/certificates/validate` | 写 | 校验证书和私钥是否匹配 |
| GET | `/api/v1/certificates/{id}` | 读 | 查询单个证书安全元数据 |
| DELETE | `/api/v1/certificates/{id}` | 写 | 删除未被启用 HTTPS 监听引用的证书 |

证书上传字段：`name`、`cert_pem`、`key_pem`。普通列表、详情、校验响应、发布预览、审计日志和导出文件不得返回私钥明文；响应只暴露 `id`、`name`、`domains`、`not_before`、`not_after`、`fingerprint`、`created_at`、`updated_at` 等安全元数据。

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

创建、更新、删除或启停规则后，需要发布新版本才会影响网关活动配置。

## 策略

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/policies` | 读 | 查询策略 |
| POST | `/api/v1/policies` | 写 | 创建策略 |
| GET | `/api/v1/policies/{id}` | 读 | 查询单个策略 |
| PUT | `/api/v1/policies/{id}` | 写 | 更新策略 |
| DELETE | `/api/v1/policies/{id}` | 写 | 删除策略 |

策略绑定字段使用 `application_ids` 和 `rule_ids`；迁移期仍兼容读取请求体中的旧 `site_ids`，但新响应只返回 `application_ids`。高级字段包括归一化、Body 检测、上传检测和动态封禁配置。

创建、更新、删除或启停策略后，需要发布新版本才会影响应用绑定规则、风险阈值和高级检测字段。

## 发布

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/releases` | 读 | 查询发布记录 |
| GET | `/api/v1/releases/preview` | 发布 | 预览发布摘要 |
| POST | `/api/v1/releases` | 发布 | 生成新发布版本 |
| POST | `/api/v1/releases/{version}/rollback` | 发布 | 回滚到历史版本 |

发布会生成网关配置并写入 `GATEWAY_CONFIG_PATH`。防护应用、规则、策略、IP 黑白名单、访问控制、限流、CC 防护、上传防护、Bot / 人机验证、动态防护和规则包导入后的可执行规则，都以发布版本作为网关生效边界；写入资源后未发布时，网关继续使用上一版活动配置。

Dashboard 的“发布记录”页面会先调用 `GET /api/v1/releases/preview` 展示模块汇总、兼容诊断和风险提示，再调用 `POST /api/v1/releases` 发布。`POST /api/v1/releases/{version}/rollback` 会把历史发布配置重新写入网关配置路径，并创建新的回滚发布记录；它不会撤销当前数据库中的防护应用、规则或策略编辑。

发布配置顶层输出 `applications`，不再输出旧 `sites` 字段。发布配置会保留旧 `rate_limits` 限流兼容字段，并输出独立 `ip_access_index` 作为 IP 黑白名单运行时索引；旧 `access_lists` 字段、接口和网关 fallback 已移除。`protection_rules` 表继续输出 CC 防护、访问控制、上传防护、Bot / 人机验证和动态防护子集。托管攻击防护规则继续位于应用 `rules` 数组中，同时带有网关可识别的 `module=attack-protection`、`category=managed`、`attack_type`、`group` 和 `priority` 元数据：

```json
{
  "rate_limits": [],
  "ip_access_index": {
    "entries": {},
    "exact": {
      "allow": {},
      "block": {}
    },
    "cidr": {
      "allow": {},
      "block": {}
    },
    "cidr_prefix_lengths": {
      "allow": {},
      "block": {}
    }
  },
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

发布预览的 `summary.ip_access_list` 包含 IP 黑白名单总数、启用数量、白名单/黑名单数量、Exact IP 数量、CIDR 数量、全局和站点作用域数量。`summary.cc_protection` 包含 CC 规则总数、启用数量和高风险配置提示。`summary.attack_protection` 包含攻击防护组数量、启用数量、观察数量、阻断数量和受影响攻击类型。`summary.access_control` 包含访问控制规则总数、启用数量、允许/观察/阻断数量和宽泛允许类风险提示。`summary.upload_protection` 包含上传防护规则总数、启用数量、扩展名规则数、大小规则数、观察/阻断数量和高风险上传限制提示。`summary.bot_protection` 包含 Bot 规则总数、启用数量、JS challenge 数量、阻断数量、观察数量和宽泛 challenge 提示。`summary.dynamic_protection` 包含动态防护规则总数、启用数量、动态令牌数量、页面动态化数量、等候室数量、阻断数量、观察数量、等候室动作数量和宽泛路径提示。

发布预览还会返回 `summary.module_matrix` 和 `summary.risk_warnings`。`module_matrix` 按防护模块汇总规则总数、启用数、观察数、阻断数、兼容来源和高风险提示，前端应优先展示模块语义；旧 `access_lists` 兼容计数不再返回。`risk_warnings` 是跨模块风险摘要，不参与网关执行；实际发布配置仍只依赖可执行规则字段、`protection_rules` 和 `ip_access_index`。

## IP 黑白名单

IP 黑白名单是独立模块，不再复用旧 `access_lists` 或访问控制写入路径。旧 `/api/v1/access-lists` 接口已移除；来源 IP/CIDR 的白名单和黑名单应通过 `/api/v1/ip-access-lists` 管理。Exact IP 会在发布时预处理成按站点作用域、名单类型和规范化 IP 键组织的哈希索引，网关热路径查询为 O(1)；CIDR 会按 IP 族和前缀长度分组，运行时只遍历已发布的前缀长度集合。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/ip-access-lists` | 读 | 查询 IP 黑白名单 |
| POST | `/api/v1/ip-access-lists` | 写 | 创建 IP 黑白名单 |
| GET | `/api/v1/ip-access-lists/{id}` | 读 | 查询 IP 黑白名单 |
| PUT | `/api/v1/ip-access-lists/{id}` | 写 | 更新 IP 黑白名单 |
| DELETE | `/api/v1/ip-access-lists/{id}` | 写 | 删除 IP 黑白名单 |

支持目标：`ip`、`cidr`。支持类型：`allow`、`block`。API 会规范化 IPv4、IPv6 和 CIDR，持久化 `normalized_value`、`ip_family`、`prefix_length` 和 `conflict_key`。管理员可以创建、更新、启停和删除；readonly 和 auditor 用户只能读取。写操作会记录 `resource_type=ip_access_list` 的审计日志。

IP 黑白名单写入后必须发布，网关才会重新生成 `ip_access_index` 并在热路径执行 Exact IP 或 CIDR 判断。

## 访问控制

访问控制接口以通用 `protection_rules` 表作为主存储，对外以 `module=access-control`、`category=access-control` 的防护规则模型呈现。当前覆盖路径、Header 和 Host 条件，支持 `allow`、`log-only` 和 `block` 动作；来源 IP/CIDR 黑白名单不再通过访问控制创建、展示或 fallback。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/access-control/rules` | 读 | 查询访问控制规则 |
| POST | `/api/v1/access-control/rules` | 写 | 创建访问控制规则 |
| GET | `/api/v1/access-control/rules/{id}` | 读 | 查询访问控制规则 |
| PUT | `/api/v1/access-control/rules/{id}` | 写 | 更新访问控制规则 |
| DELETE | `/api/v1/access-control/rules/{id}` | 写 | 删除访问控制规则 |

列表支持过滤：

- `application_id`：防护应用 ID。迁移期兼容旧 `site_id` 查询参数。
- `enabled`：`true` 或 `false`。

请求示例：

```json
{
  "name": "管理后台路径阻断",
  "application_id": 1,
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
- `match.target` 支持 `path`、`header`、`host`。提交 `ip` 或 `cidr` 会被拒绝，来源 IP/CIDR 请使用 IP 黑白名单接口。
- `match.value` 用于 Header 值；`match.path` 用于路径条件；`match.host` 用于 Host 条件。
- `match.path` 必须以 `/` 开头，`match.path_match` 支持 `exact`、`prefix`；prefix 匹配按路径段边界处理，`/admin` 不匹配 `/admin2`。
- `match.header_name` 为 Header 条件必填，Header `operator` 支持 `exact`、`contains`。
- Host `operator` 支持 `exact`、`suffix`。
- `match.methods` 支持 `GET`、`POST`、`PUT`、`PATCH`、`DELETE`、`HEAD`、`OPTIONS`，空数组表示全部方法。
- `action.type` 支持 `allow`、`log-only`、`block`。
- `priority` 为正整数，用于发布配置和网关排序。

管理员可以创建、更新和删除访问控制规则；readonly 和 auditor 用户只能读取。写操作会记录 `resource_type=access_control_rule` 的审计日志。

## 上传防护

上传防护接口以通用 `protection_rules` 表作为主存储，对外以 `module=upload-protection`、`category=upload` 的防护规则模型呈现。当前阶段覆盖上传路径、HTTP 方法、危险扩展名和上传大小限制，支持 `log-only` 和 `block` 动作；旧上传防护记录和策略级高级上传检测字段继续保留用于兼容。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/upload-protection/rules` | 读 | 查询上传防护规则 |
| POST | `/api/v1/upload-protection/rules` | 写 | 创建上传防护规则 |
| GET | `/api/v1/upload-protection/rules/{id}` | 读 | 查询上传防护规则 |
| PUT | `/api/v1/upload-protection/rules/{id}` | 写 | 更新上传防护规则 |
| DELETE | `/api/v1/upload-protection/rules/{id}` | 写 | 删除上传防护规则 |

列表支持过滤：

- `application_id`：防护应用 ID。迁移期兼容旧 `site_id` 查询参数。
- `enabled`：`true` 或 `false`。

请求示例：

```json
{
  "name": "危险脚本上传阻断",
  "application_id": 1,
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

Bot / 人机验证接口以通用 `protection_rules` 表作为主存储，对外以 `module=bot-protection`、`category=challenge` 的防护规则模型呈现。当前阶段支持本地 JavaScript challenge、本地算术 captcha、轻量行为评分、粗粒度设备信号绑定、搜索引擎 UA 绕过、失败说明和隐私提示；不包含第三方 captcha 服务、反向 DNS 搜索引擎验证、长期设备画像、动态令牌或等候室。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/bot-protection/rules` | 读 | 查询 Bot 验证规则 |
| POST | `/api/v1/bot-protection/rules` | 写 | 创建 Bot 验证规则 |
| GET | `/api/v1/bot-protection/rules/{id}` | 读 | 查询 Bot 验证规则 |
| PUT | `/api/v1/bot-protection/rules/{id}` | 写 | 更新 Bot 验证规则 |
| DELETE | `/api/v1/bot-protection/rules/{id}` | 写 | 删除 Bot 验证规则 |

列表支持过滤：

- `application_id`：防护应用 ID。迁移期兼容旧 `site_id` 查询参数。
- `enabled`：`true` 或 `false`。

请求示例：

```json
{
  "name": "后台路径 JS Challenge",
  "application_id": 1,
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
    "failure_action": "block",
    "behavior_enabled": false,
    "behavior_threshold": 60,
    "device_binding": false,
    "search_engine_bypass": false,
    "failure_message": "验证失败，请稍后重试。",
    "privacy_notice": "LiteWaf 仅使用本地挑战信号完成验证。"
  }
}
```

响应中的规则会补齐 `module=bot-protection`、`category=challenge`、`action.type` 和时间字段。

支持字段：

- `module` 固定为 `bot-protection`，`category` 固定为 `challenge`；创建和更新时可省略，API 会填充默认值。
- `match.path` 必须以 `/` 开头。
- `match.path_match` 支持 `exact`、`prefix`；prefix 匹配按路径段边界处理，`/admin` 不匹配 `/admin2`。
- `match.methods` 支持 `GET`、`POST`、`PUT`、`PATCH`、`DELETE`、`HEAD`、`OPTIONS`，空数组表示全部方法。
- `challenge.mode` 支持 `js-challenge`、`captcha`；`captcha` 为网关本地算术挑战，不需要第三方凭据。
- `challenge.verify_ttl_sec` 必须大于 `0` 且不超过 `86400`。
- `challenge.failure_action` 支持 `block`、`log-only`。
- `challenge.behavior_enabled` 启用轻量行为评分；启用时 `challenge.behavior_threshold` 必须在 `1` 到 `100` 之间。
- `challenge.device_binding` 启用粗粒度设备信号绑定，网关会将 pass token 与 User-Agent / Accept-Language 派生信号绑定，但不记录原始信号。
- `challenge.search_engine_bypass` 启用已知搜索引擎 UA 绕过；当前不做反向 DNS 验证，命中时会写入 Bot 结果日志。
- `challenge.failure_message` 最多 `240` 字符，用于本地挑战或阻断说明。
- `challenge.privacy_notice` 最多 `360` 字符，用于向用户说明本地验证信号使用边界。
- `action.type` 可省略；传入时必须与 `challenge.failure_action` 一致。
- `priority` 不能为负数，发布和网关按较小值优先执行。

管理员可以创建、更新和删除 Bot 验证规则；readonly 和 auditor 用户只能读取。写操作会记录 `resource_type=bot_protection_rule` 的审计日志。

## 动态防护 / 等候室

动态防护接口以通用 `protection_rules` 表作为主存储，对外以 `module=dynamic-protection` 的防护规则模型呈现。当前阶段支持 `dynamic-token`、`page-mutation` 和 `waiting-room` 三类规则，不包含 captcha、行为评分、设备指纹、完整 JavaScript 混淆或分布式全局队列。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/dynamic-protection/rules` | 读 | 查询动态防护规则 |
| POST | `/api/v1/dynamic-protection/rules` | 写 | 创建动态防护规则 |
| GET | `/api/v1/dynamic-protection/rules/{id}` | 读 | 查询动态防护规则 |
| PUT | `/api/v1/dynamic-protection/rules/{id}` | 写 | 更新动态防护规则 |
| DELETE | `/api/v1/dynamic-protection/rules/{id}` | 写 | 删除动态防护规则 |

列表支持过滤：

- `application_id`：防护应用 ID。迁移期兼容旧 `site_id` 查询参数。
- `enabled`：`true` 或 `false`。
- `category`：`dynamic-token`、`page-mutation`、`waiting-room`。

动态令牌请求示例：

```json
{
  "name": "后台动态令牌",
  "application_id": 1,
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
  "application_id": 1,
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
  "application_id": 1,
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

限流接口作为旧入口继续保留，用于兼容既有客户端和发布字段。后台新建 URL 频率限制、登录防爆破、API 调用限流和临时封禁规则时，推荐使用“CC 防护”模块；CC 防护会以 `module=cc-protection`、`category=rate-limit` 呈现同类规则。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/rate-limits` | 读 | 查询限流规则 |
| POST | `/api/v1/rate-limits` | 写 | 创建限流规则 |
| GET | `/api/v1/rate-limits/{id}` | 读 | 查询限流规则 |
| PUT | `/api/v1/rate-limits/{id}` | 写 | 更新限流规则 |
| DELETE | `/api/v1/rate-limits/{id}` | 写 | 删除限流规则 |

限流支持 IP、URI、站点维度，重复违规可触发临时封禁。

限流兼容规则写入后需要发布，网关才会更新旧 `rate_limits` 兼容字段。新建 URL 频率、登录爆破和 API 限流规则时优先使用 CC 防护。

## CC 防护

CC 防护接口以通用 `protection_rules` 表作为主存储，对外以 `module=cc-protection`、`category=rate-limit` 的防护规则模型呈现。当前覆盖 URL 访问频率限制、登录防爆破和 API 调用限流；旧限流配置继续保留为兼容入口，未迁移旧记录仍会作为 `legacy-only` 规则出现在 CC 防护列表中。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/cc-protection/rules` | 读 | 查询 CC 防护规则 |
| POST | `/api/v1/cc-protection/rules` | 写 | 创建 CC 防护规则 |
| POST | `/api/v1/cc-protection/preview` | 读 | 使用样本请求事实模拟预览 CC 规则命中 |
| GET | `/api/v1/cc-protection/rules/{id}` | 读 | 查询 CC 防护规则 |
| PUT | `/api/v1/cc-protection/rules/{id}` | 写 | 更新 CC 防护规则 |
| DELETE | `/api/v1/cc-protection/rules/{id}` | 写 | 删除 CC 防护规则 |

列表支持过滤：

- `application_id`：防护应用 ID。迁移期兼容旧 `site_id` 查询参数。
- `enabled`：`true` 或 `false`。

请求示例：

```json
{
  "name": "登录接口防爆破",
  "application_id": 1,
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

高级 CC 能力支持 `path_match=glob`，以及 `not_found_frequency`、`attack_frequency`、`session`、`device` 计数维度。`session` 计数可通过 `limit.session_source` 和 `limit.session_name` 指定 Cookie 或 Header；`device` 当前使用 `device_strategy=coarse`。`POST /api/v1/cc-protection/preview` 只返回匹配、计数键说明、风险和 partial 解释，不修改规则、发布记录或网关计数。

CC 防护规则写入后需要发布，网关才会更新 `protection_rules` 中的 `module=cc-protection` 规则。

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

高级规则生态接口用于本地规则包预览、导入、来源追踪和规则测试。规则社区增强进一步提供远程目录、显式更新审核、信任密钥和贡献导出；付费规则源、云账号绑定、远程仓库推送和自动激活仍不在当前范围。

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
    "license": "Apache-2.0",
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

`package` 为空对象时，API 使用内置默认规则包进行预览或导入。签名状态包括 `verified`、`unsigned`、`invalid`、`untrusted-key`、`revoked-key`、`expired`；签名作为来源状态和发布预览警告，不强制拒绝未签名本地包。

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

## 规则社区增强

规则社区增强接口用于社区目录、远程规则包预览、显式更新审核、信任密钥管理和贡献导出。目录同步、远程预览和更新检查都不会自动创建、启用、禁用或发布规则；网关运行时不依赖目录、信任库或导出产物。

### 社区目录

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/rule-community/catalogs` | 读 | 查询目录来源 |
| POST | `/api/v1/rule-community/catalogs` | 写 | 创建目录来源 |
| GET | `/api/v1/rule-community/catalogs/{id}` | 读 | 查询目录来源 |
| PUT | `/api/v1/rule-community/catalogs/{id}` | 写 | 更新目录来源 |
| DELETE | `/api/v1/rule-community/catalogs/{id}` | 写 | 删除目录来源 |
| POST | `/api/v1/rule-community/catalogs/{id}/sync` | 写 | 同步目录包元数据 |
| GET | `/api/v1/rule-community/catalogs/{id}/packages` | 读 | 查询目录包列表 |

目录来源字段：`name`、`source`、`enabled`、`timeout_sec`。`source` 支持 HTTPS 或本地文件路径，不支持明文 HTTP。同步返回目录包元数据和签名状态；同步失败会记录 `last_error`，并保留上次成功同步的包元数据。

### 远程预览和更新

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/v1/rule-community/catalogs/{id}/packages/{package_id}/preview` | 写 | 预览远程规则包 |
| POST | `/api/v1/rule-community/catalogs/{id}/packages/{package_id}/update-preview` | 写 | 预览待更新规则差异 |
| POST | `/api/v1/rule-community/catalogs/{id}/packages/{package_id}/apply-update` | 写 | 显式应用规则包更新 |

远程预览返回 `package`、`added`、`changed`、`skipped`、`invalid`、`warnings`、`compatibility_status` 和 `source_catalog_id`。更新预览额外返回 `removed`、`unchanged`、当前/候选版本、当前/候选 checksum 和 `signature_status`。应用更新按 `package_id + package_rule_id` 更新，不会因目录同步自动激活。

### 信任密钥

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/rule-community/trust-keys` | 读 | 查询信任密钥公开元数据 |
| POST | `/api/v1/rule-community/trust-keys` | 写 | 创建信任密钥 |
| PUT | `/api/v1/rule-community/trust-keys/{id}` | 写 | 更新、禁用或撤销信任密钥 |

请求字段：`key_id`、`algorithm`、`owner`、`public_key`、`enabled`、`revoked`、`expires_at`。响应不会返回 `public_key` 或私钥材料。信任决策会应用到本地包预览/导入、远程包预览、更新预览、更新应用和发布预览。

### 外部规则源 Provider

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/rule-community/providers` | 读 | 查询 Provider 配置和健康状态 |
| POST | `/api/v1/rule-community/providers` | 写 | 创建 Provider |
| GET | `/api/v1/rule-community/providers/{id}` | 读 | 查询 Provider 详情 |
| PUT | `/api/v1/rule-community/providers/{id}` | 写 | 更新 Provider |
| DELETE | `/api/v1/rule-community/providers/{id}` | 写 | 删除 Provider |
| POST | `/api/v1/rule-community/providers/{id}/validate` | 写 | 校验 Provider 凭据状态 |
| POST | `/api/v1/rule-community/providers/{id}/sync` | 写 | 同步 Provider 目录包元数据 |
| POST | `/api/v1/rule-community/providers/{id}/retry` | 写 | 手动重试同步 |
| GET | `/api/v1/rule-community/providers/{id}/packages` | 读 | 查询 Provider 包列表 |
| POST | `/api/v1/rule-community/providers/{id}/packages/{package_id}/preview` | 写 | 预览 Provider 包 |
| POST | `/api/v1/rule-community/providers/{id}/packages/{package_id}/import` | 写 | 显式导入 Provider 包 |

当前支持 `provider_type=https-catalog`，认证方式支持 `auth_mode=none` 和 `auth_mode=bearer-token`。创建和更新请求字段包括 `name`、`provider_type`、`endpoint`、`auth_mode`、`enabled`、`timeout_sec`、`retry_policy`、`credential` 和只写字段 `credential_secret`。

创建示例：

```json
{
  "name": "Commercial rule feed",
  "provider_type": "https-catalog",
  "endpoint": "https://rules.example.com/catalog.json",
  "auth_mode": "bearer-token",
  "enabled": true,
  "timeout_sec": 5,
  "retry_policy": {
    "max_attempts": 3,
    "backoff_sec": 60
  },
  "credential": {
    "alias": "prod-feed"
  },
  "credential_secret": "write-only-token"
}
```

响应只返回凭据公开元数据，例如 `alias`、`fingerprint`、`last_four`、`last_validated_at` 和 `status`，不会返回原始密钥。同步失败会更新 `health_status`、`sync_status`、`last_error`、`attempt_count`、`next_retry_at` 和 `retry_exhausted`，并保留上一次成功同步的包元数据。

Provider 包预览返回普通规则包预览字段，并额外包含 `provider_id`、`provider_name`、`provider_package_ref`、`entitlement_warnings`、`retry_state`、`trust_status`、`blocked` 和 `block_reason`。预览和同步都不会创建、启用、停用、删除、发布或修改规则；只有 `/import` 会在管理员明确确认后导入包内规则。

### 贡献导出

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/v1/rule-community/export/preview` | 写 | 预览导出包、校验规则和元数据 |
| POST | `/api/v1/rule-community/export` | 写 | 生成贡献规则包产物 |

导出请求字段：`package_id`、`name`、`version`、`author`、`license`、`compatibility`、`rule_ids`、`signing_key_id`。导出产物包含规则包 JSON、checksum、规则数和贡献提示，不包含私钥、API Token、Authorization/Cookie、原始流量样本、数据库连接串或部署密钥。

### 规则社区二期

规则社区二期接口用于账号化/订阅化规则源、贡献推送、自动导入建议队列和误报反馈闭环。所有写接口都需要写权限；只读角色只能查看状态。`credential_secret` 是写入字段，响应不会返回原始密钥。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/rule-community/account-sources` | 读 | 查询账号规则源 |
| POST | `/api/v1/rule-community/account-sources` | 写 | 创建账号规则源 |
| GET | `/api/v1/rule-community/account-sources/{id}` | 读 | 查询账号规则源详情 |
| PUT | `/api/v1/rule-community/account-sources/{id}` | 写 | 更新账号规则源 |
| DELETE | `/api/v1/rule-community/account-sources/{id}` | 写 | 删除账号规则源 |
| POST | `/api/v1/rule-community/account-sources/{id}/refresh` | 写 | 刷新订阅状态并生成待审建议 |
| GET | `/api/v1/rule-community/contribution-targets` | 读 | 查询贡献推送目标 |
| POST | `/api/v1/rule-community/contribution-targets` | 写 | 创建贡献推送目标 |
| GET | `/api/v1/rule-community/contribution-pushes` | 读 | 查询贡献推送记录 |
| POST | `/api/v1/rule-community/contribution-pushes/preview` | 写 | 预览贡献推送 |
| POST | `/api/v1/rule-community/contribution-pushes` | 写 | 执行贡献推送 |
| GET | `/api/v1/rule-community/review-queue` | 读 | 查询自动导入建议队列 |
| PUT | `/api/v1/rule-community/review-queue/{id}` | 写 | 批准、忽略或标记建议失败 |
| GET | `/api/v1/rule-community/feedback` | 读 | 查询误报反馈 |
| POST | `/api/v1/rule-community/feedback` | 写 | 创建误报反馈并生成候选建议 |
| GET | `/api/v1/rule-community/feedback-suggestions` | 读 | 查询误报候选建议 |
| POST | `/api/v1/rule-community/feedback-suggestions/{id}/test` | 写 | 测试候选建议 |
| PUT | `/api/v1/rule-community/feedback-suggestions/{id}` | 写 | 批准或拒绝候选建议 |

账号源创建示例：

```json
{
  "name": "Paid community feed",
  "provider_type": "https-catalog",
  "endpoint": "https://rules.example.com/catalog.json",
  "enabled": true,
  "timeout_sec": 5,
  "credential": {
    "alias": "prod-feed"
  },
  "credential_secret": "write-only-token"
}
```

订阅刷新、队列项创建、误报反馈和候选建议都不会自动启用、禁用、删除、发布或修改规则。网关发布 payload 不包含账号、订阅、队列、推送或反馈元数据。

## 日志和观测

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/access-logs` | 读 | 查询访问日志 |
| GET | `/api/v1/blocked-rejected-records` | 读 | 查询拦截/拒绝记录和触发解释 |
| GET | `/api/v1/attack-logs` | 读 | 查询 WAF 事件 |
| GET | `/api/v1/observability/summary` | 读 | 查询汇总指标 |
| GET | `/api/v1/protection/overview` | 读 | 查询跨模块防护概览 |
| GET | `/api/v1/dynamic-bans` | 读 | 查询活动动态封禁 |
| POST | `/api/v1/dynamic-bans/unban` | 写 | 手动释放应用/IP 动态封禁 |
| GET | `/api/v1/dynamic-bans/clears` | 网关令牌 | 查询手动释放增量供网关同步 |
| POST | `/api/v1/ingest/access-logs` | 网关令牌 | 接收访问日志 |
| POST | `/api/v1/ingest/waf-events` | 网关令牌 | 接收 WAF 事件 |

攻击日志支持 `module`、`attack_type` 和 `action` 过滤。例如：

```text
GET /api/v1/attack-logs?module=attack-protection&attack_type=sqli
GET /api/v1/attack-logs?module=ip-access-list&action=block
GET /api/v1/attack-logs?module=access-control&action=block
GET /api/v1/attack-logs?module=upload-protection&action=block
GET /api/v1/attack-logs?module=bot-protection&challenge_result=failed
GET /api/v1/attack-logs?module=dynamic-protection&dynamic_result=token-failed
```

拦截/拒绝记录以访问日志中的 `disposition=blocked` 或 `disposition=rejected` 为主记录，并尽量关联同 `request_id` 的 WAF 事件、同应用/IP/监听的动态封禁，或访问日志自身的 `reason_code` / `reason`。支持过滤：`since`、`until`、`application_id`、`listener_port`、`scheme`、`host`、`client_ip`、`method`、`uri`、`status`、`disposition`、`module`、`action`、`trigger_source`、`limit` 和 `offset`。`trigger_source` 可能为：

- `waf-event`：同请求 ID 的 WAF 事件，优先展示模块、规则、动作和摘要。
- `dynamic-ban`：动态封禁上下文，展示封禁原因、来源、状态和剩余时长。
- `access-log`：访问日志自带的网关拒绝/阻断原因，例如未知 Host。
- `unclassified`：只有访问日志可用，系统不会伪造模块或规则身份。

```text
GET /api/v1/blocked-rejected-records?disposition=blocked
GET /api/v1/blocked-rejected-records?trigger_source=access-log
GET /api/v1/blocked-rejected-records?module=attack-protection&action=block
```

访问日志摄取可携带有界 `reason_code` 和 `reason` 字段，用于解释没有 WAF 事件的网关拒绝或阻断。日志响应不得包含完整请求体、Cookie、Authorization、动态 token、captcha 答案、签名密钥或未截断的匹配值。

`/api/v1/protection/overview` 返回模块化防护概览，包含 `modules` 和 `risks`。`modules` 固定覆盖已实现模块：CC 防护、攻击防护、IP 黑白名单、访问控制、上传防护、Bot / 人机验证、动态防护和高级规则生态；每个模块包含 `key`、`label`、`category`、`route`、`log_module`、`rules`、`enabled`、`observe`、`block`、`allow`、`compatibility_source`、`warnings` 和 `evidence`。计数来自真实规则、日志和发布预览数据；没有数据时返回零值或空数组，不返回 mock 行。`risks` 从各模块真实高风险提示派生，用于后台跨模块风险摘要。

攻击防护事件字段包括 `module`、`category`、`attack_type`、`group_name`、`rule_name`、`rule_id`、`target`、`action`、`score`、`summary` 和 `disposition`。观测汇总中的 `attack_protection` 按 `attack_type|action|disposition` 维度统计。

访问控制事件字段包括 `module=access-control`、`category=access-control`、`rule_name`、`rule_id`、`target`、`action` 和 `disposition`。观测汇总中的 `access_control` 按 `action|disposition` 维度统计，例如 `block|blocked`、`log-only|observed` 或 `allow|allowed`。

IP 黑白名单事件字段包括 `module=ip-access-list`、`category=ip-access-list`、`ip_access_list_id`、`ip_list_kind`、`ip_list_target`、`client_ip`、`action` 和 `disposition`。观测汇总中的 `ip_access_list` 按 `kind|target|action|disposition` 维度统计，例如 `block|ip|block|blocked` 或 `allow|cidr|allow|allowed`。

上传防护事件字段包括 `module=upload-protection`、`category=upload`、`rule_name`、`rule_id`、`target`、`action`、`disposition`、`threshold` 和 `upload_metadata`。观测汇总中的 `upload_protection` 按 `action|disposition` 维度统计，例如 `block|blocked` 或 `log-only|observed`。

Bot 验证事件字段包括 `module=bot-protection`、`category=challenge`、`rule_name`、`rule_id`、`target`、`action`、`disposition`、`challenge_mode` 和 `challenge_result`。`challenge_result` 支持 `issued`、`passed`、`failed`；观测汇总中的 `bot_protection` 按 `challenge_result|action|disposition` 维度统计，例如 `issued|block|blocked`、`passed|pass|proxied` 或 `failed|block|blocked`。

动态防护事件字段包括 `module=dynamic-protection`、`category`、`rule_name`、`rule_id`、`target`、`action`、`disposition` 和 `advanced_target`。`advanced_target` 承载动态结果，可通过 `dynamic_result` 查询参数过滤，常见值包括 `token-issued`、`token-passed`、`token-failed`、`mutation-applied`、`mutation-skipped`、`queue-admitted`、`queue-queued`、`queue-blocked` 和 `queue-observed`。观测汇总中的 `dynamic_protection` 按 `category|result|action|disposition` 维度统计。

### 活动动态封禁和手动解封

活动动态封禁来自网关上报的 `event_type=dynamic-ban` WAF 事件，API 会维护应用/IP 维度的活动封禁投影。列表接口支持 `application_id`、`listener_port`、`scheme`、`client_ip`、`status`、`limit` 和 `offset` 过滤；迁移期兼容旧 `site_id` 查询参数。过期或已清理的封禁不会作为默认活动封禁返回。

```bash
curl -H "Authorization: Bearer <token>" "http://localhost:18080/api/v1/dynamic-bans?application_id=1&client_ip=203.0.113.41"
```

返回字段包括 `application_id`、`client_ip`、`ban_reason`、`source`、`source_event_id`、`ban_duration_sec`、`ban_remaining_sec`、`status`、`revision`、`created_at`、`expires_at`、`cleared_at` 和 `updated_at`。无匹配数据时返回空 `items`，不返回演示行。

管理员可按应用和有效客户端 IP 手动释放封禁：

```bash
curl -X POST "http://localhost:18080/api/v1/dynamic-bans/unban" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"application_id":1,"client_ip":"203.0.113.41"}'
```

释放结果包含 `application_id`、`client_ip`、`status`、`revision`、`cleared_at` 和 `message`。`status=cleared` 表示存在活动封禁并已标记清理；`status=no-op` 表示目标不存在、已过期或已清理，接口仍会生成清理 revision 供网关消费，便于重复点击或重试时保持幂等。readonly 和 auditor 角色只能查看，不能调用释放接口。

网关使用摄取令牌读取增量清理 feed：

```bash
curl -H "Authorization: Bearer <gateway-token>" "http://localhost:18080/api/v1/dynamic-bans/clears?since_revision=0&limit=100"
```

该接口只返回有界应用/IP、状态、revision 和消息，不包含请求体、Cookie、Authorization、网关令牌或动态 token。网关在 worker 定时同步后删除本地应用/IP 对应动态封禁 key，请求热路径不调用控制面 API；实际解除阻断存在一个同步间隔内的传播延迟。

## 审计和系统

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/audit-logs` | 审计/管理员 | 查询审计日志 |
| GET | `/api/v1/version` | 读 | 查询版本 |
| GET | `/metrics` | 环境变量控制 | Prometheus 文本指标 |
