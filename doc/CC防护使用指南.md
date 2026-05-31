# CC 防护使用指南

CC 防护用于限制高频访问、登录爆破和 API 调用滥用。当前阶段只实现 `module=cc-protection`、`category=rate-limit` 的频率限制规则，不包含攻击防护、上传防护、Bot、人机验证或动态防护模块。

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

## API

```text
GET    /api/v1/cc-protection/rules
POST   /api/v1/cc-protection/rules
GET    /api/v1/cc-protection/rules/{id}
PUT    /api/v1/cc-protection/rules/{id}
DELETE /api/v1/cc-protection/rules/{id}
```

列表支持 `site_id` 和 `enabled` 过滤。

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

- `path_match`：`exact`、`prefix`。
- `methods`：空数组表示全部方法。
- `counter`：`client_ip`、`client_ip_path`、`global`。
- `action`：`log-only`、`block`、`rate-limit`、`ban`。

prefix 匹配按路径段边界处理，例如 `/admin` 匹配 `/admin` 和 `/admin/users`，不匹配 `/admin2`。

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
