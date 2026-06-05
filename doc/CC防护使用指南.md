# CC 防护使用指南

CC 防护用于限制高频访问、登录爆破、API 调用滥用、404 扫描和攻击命中频率。当前规则以 `module=cc-protection`、`category=rate-limit` 的频率限制模型管理，不包含上传防护、Bot、人机验证或动态防护模块。

## 后台入口

后台菜单进入：

```text
CC 防护
```

页面使用真实 API 数据，不写 mock 数据。只读角色只能查看；管理员可以新增、编辑和删除规则。

## 推荐模板

### 登录接口防爆破

```text
路径：/api/login
匹配方式：exact
方法：POST
统计对象：client_ip
阈值：10 次 / 60 秒
动作：ban
封禁：600 秒
```

### API 调用频率限制

```text
路径：/api/
匹配方式：prefix
方法：全部
统计对象：client_ip_path
阈值：120 次 / 60 秒
动作：rate-limit
封禁：60 秒
```

### 全站基础 CC 防护

```text
路径：/
匹配方式：prefix
方法：全部
统计对象：client_ip
阈值：300 次 / 60 秒
动作：rate-limit
封禁：300 秒
```

### 404 扫描频率

```text
路径：/api/*
匹配方式：glob
方法：全部
统计对象：not_found_frequency
阈值：20 次 / 60 秒
动作：rate-limit
```

### 会话级登录限制

```text
路径：/api/login
匹配方式：exact
方法：POST
统计对象：session
会话来源：cookie
会话名称：sid
阈值：8 次 / 60 秒
动作：block
```

## API

```text
GET    /api/v1/cc-protection/rules
POST   /api/v1/cc-protection/rules
GET    /api/v1/cc-protection/rules/{id}
PUT    /api/v1/cc-protection/rules/{id}
DELETE /api/v1/cc-protection/rules/{id}
POST   /api/v1/cc-protection/preview
```

列表支持 `site_id` 和 `enabled` 过滤。模拟预览接口只读取当前配置和请求样本，不会修改网关计数、发布记录或活动配置；返回命中的规则、计数维度、计数键说明、阈值窗口、动作和风险提示。

## 发布和网关执行

发布配置同时保留旧 `rate_limits` 字段，并输出：

```json
{
  "protection_rules": [
    {
      "module": "cc-protection",
      "category": "rate-limit"
    }
  ]
}
```

网关优先执行 `protection_rules` 中的 CC 防护规则；如果没有 CC 防护规则，则回退旧 `rate_limits`。CC 防护执行在攻击防护规则之前。

当前支持：

- `path_match`：`exact`、`prefix`、`glob`。
- `methods`：空数组表示全部方法。
- `counter`：`client_ip`、`client_ip_path`、`global`、`not_found_frequency`、`attack_frequency`、`session`、`device`。
- `action`：`log-only`、`block`、`rate-limit`、`ban`。

prefix 匹配按路径段边界处理，例如 `/admin` 匹配 `/admin` 和 `/admin/users`，不匹配 `/admin2`。

`glob` 用于受限路径通配，不支持 `**`、正则或复杂字符集。`session` 计数需要配置 Cookie 或 Header 名称；`device` 使用粗粒度请求信号派生计数键，不记录原始指纹、Cookie 或 Authorization。`not_found_frequency` 在真实 404 响应后增量计数，并在后续匹配请求进入网关时预检限制。`attack_frequency` 基于同请求攻击规则命中信号增量计数，不在热路径查询控制面日志。

发布预览会统计高级计数规则和 glob 规则数量，并对全站低阈值、宽泛 glob、阻断类动作等配置返回高风险提示。后台 CC 页面也会在规则编辑和模拟预览中展示这些真实 API 返回的风险信息。

## 日志

CC 防护命中会写入 WAF 事件日志，关键字段包括：

```json
{
  "event_type": "rate-limit",
  "module": "cc-protection",
  "category": "rate-limit",
  "rule_name": "登录接口防爆破",
  "counter": "client_ip",
  "threshold": 10,
  "window_sec": 60,
  "action": "ban",
  "disposition": "blocked"
}
```

攻击日志页面会展示模块、规则名称、计数维度、阈值和窗口。

## 验证状态

本地已完成：

```powershell
cd D:\Project\web_safe\codes\litewaf-api
go test ./...

cd D:\Project\web_safe\codes\litewaf-dashboard
npm run build

cd D:\Project\web_safe\codes\litewaf-api
docker compose -f deploy/docker-compose.yml config
```

当前机器 Docker daemon 不可用，OpenResty 网关端到端场景需要在可用 Docker/OpenResty 环境中复测：

- 登录接口防爆破。
- API 调用频率限制。
- 全站基础 CC 防护。
- `/admin` prefix 不误命中 `/admin2`。
- 发布回滚后规则恢复。
- 攻击日志包含 CC 防护解释字段。

Followup-5 已新增高级 CC smoke 脚本：

```powershell
cd D:\Project\web_safe\codes\litewaf-gateway
powershell -ExecutionPolicy Bypass -File .\scripts\cc-advanced-smoke.ps1
```

脚本覆盖 glob 匹配、会话计数、粗粒度设备计数、404 频率、攻击命中频率和旧计数兼容。当前机器 Docker Desktop Linux engine 不可用时，可先完成 JSON 和 PowerShell 语法检查，待 Docker/OpenResty 环境恢复后运行完整 smoke。
