# Bot 人机验证使用指南

本文档说明 LiteWaf 当前 Bot / 人机验证模块的使用边界和安全上线方式。当前阶段只实现轻量 JavaScript challenge，用于保护后台、登录页等浏览器访问路径，降低简单脚本和低成本爬虫直接访问的概率。

## 当前能力

- 后台模块：`Bot / 人机验证`。
- 发布模块标识：`module=bot-protection`，`category=challenge`。
- challenge 模式：仅支持 `js-challenge`。
- 匹配条件：站点、路径、`exact` / `prefix` 路径匹配、HTTP 方法、启用状态和优先级。
- 失败动作：`block` 或 `log-only`。
- 网关执行顺序：访问控制、CC 防护、上传防护之后，攻击防护和高级规则之前。
- 验证方式：网关本地签发和验证短期 cookie，不在请求热路径调用控制面 API。
- 日志字段：`challenge_mode`、`challenge_result`、`module`、`category`、`rule_name`、`action`、`disposition`。

## 不包含的能力

当前版本不包含第三方 captcha、行为评分、设备指纹、动态令牌混淆、等待室、搜索引擎识别或完整 Bot 检测平台能力。JavaScript challenge 可以拦住简单 HTTP 客户端，但不能阻止具备浏览器自动化能力的攻击者。

## 推荐上线流程

1. 先用 `log-only` 规则观察目标路径。
2. 只选择明确的浏览器访问路径，例如 `/admin`、`/login` 或管理后台前缀。
3. 避免直接对 API、Webhook、健康检查、静态资源或移动端接口启用阻断。
4. 通过攻击日志筛选 `module=bot-protection`，确认 `challenge_result` 分布。
5. 确认误伤可接受后，将失败动作从 `log-only` 调整为 `block`。
6. 发布配置，并保留上一版本用于快速回滚。

## 规则示例

后台路径阻断：

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

登录路径观察：

```json
{
  "name": "登录路径 Bot 观察",
  "site_id": 1,
  "enabled": true,
  "priority": 90,
  "match": {
    "path": "/login",
    "path_match": "exact",
    "methods": ["GET", "POST"]
  },
  "challenge": {
    "mode": "js-challenge",
    "verify_ttl_sec": 300,
    "failure_action": "log-only"
  }
}
```

## 网关配置

生产环境建议设置稳定的 challenge 签名密钥：

```text
LITEWAF_CHALLENGE_SECRET=<random-long-secret>
```

如果未设置，网关会使用发布配置版本作为兜底签名材料。这样能保持本地验证可用，但发布版本变化会让旧 cookie 更快失效。

## 日志和排查

查询 challenge 发放：

```bash
curl -H "Authorization: Bearer <token>" "http://localhost:18080/api/v1/attack-logs?module=bot-protection&challenge_result=issued"
```

查询验证失败：

```bash
curl -H "Authorization: Bearer <token>" "http://localhost:18080/api/v1/attack-logs?module=bot-protection&challenge_result=failed"
```

查询验证通过：

```bash
curl -H "Authorization: Bearer <token>" "http://localhost:18080/api/v1/attack-logs?module=bot-protection&challenge_result=passed"
```

`issued` 表示网关返回 JS challenge，`passed` 表示请求携带有效未过期验证 cookie 并继续后续防护链路，`failed` 表示验证 cookie 无效或过期；在 `block` 规则下失败会返回 403，在 `log-only` 规则下失败只记录事件并继续后续检查。

## 验证脚本

网关目录提供 Bot smoke：

```powershell
cd D:\Project\web_safe\codes\litewaf-gateway
powershell -ExecutionPolicy Bypass -File scripts\bot-protection-smoke.ps1
```

脚本会验证首次 challenge、携带 cookie 后放行到上游、无效/过期 cookie 阻断、`log-only` 观察、`/admin` 与 `/admin2` 路径边界，以及 Bot 保护先于托管攻击规则执行。
