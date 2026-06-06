# Bot 防护使用指南

Bot / 人机验证用于在敏感路径前增加轻量验证。当前实现保持本地化：网关不在热路径访问控制面，也不依赖第三方 captcha 服务。

## 支持能力

- `js-challenge`：发放本地签名 cookie，通过后在 TTL 内放行。
- `captcha`：发放本地算术 captcha，答对后写入本地签名 cookie。
- 行为评分：按 User-Agent、Accept、Accept-Language 等轻量信号计算 0 到 100 分；达到阈值才触发挑战。
- 设备信号绑定：可将 pass token 与粗粒度 User-Agent / Accept-Language 派生信号绑定。
- 搜索引擎绕过：可按已知搜索引擎 User-Agent 绕过挑战，并记录 `bot_result=search-engine-bypass`。
- 失败说明和隐私提示：可配置展示给用户的本地挑战说明。

## 推荐配置

- 后台路径：优先使用 `js-challenge`，失败动作先用 `log-only` 观察，再切换 `block`。
- 登录路径：可启用行为评分，阈值建议从 `60` 开始观察。
- 高风险路径：可使用本地 `captcha`，并开启设备信号绑定。
- 搜索引擎入口：只有明确需要 SEO 抓取时才开启搜索引擎绕过。

## 发布和上线

新增、编辑、删除或启停 Bot / 人机验证规则后，必须在后台“发布记录”发布新版本，或调用 `POST /api/v1/releases`，网关才会执行新的 challenge、captcha、行为评分或设备信号配置。

推荐上线步骤：

1. 先对明确路径配置 `log-only`，例如 `/admin` 或 `/login`。
2. 发布新版本后，通过攻击日志筛选 `module=bot-protection`，观察 `challenge_result`、`bot_result` 和误伤情况。
3. 确认浏览器、搜索引擎和关键客户端兼容后，再切换为 `block` 并再次发布。
4. 保留上一发布版本，出现误伤时可在“发布记录”回滚。

## 限制

- 本地 captcha 不是第三方验证码服务，不能替代商业风控。
- 搜索引擎绕过当前只按 User-Agent 判断，不做反向 DNS 验证，可能被伪造。
- 设备信号绑定不保存原始指纹，只使用本地签名派生信号；客户端 UA 或语言变化可能导致 token 失效。
- 当前不做长期行为画像、跨实例设备库或分布式 Bot 信誉。

## 可观测字段

Bot 事件会写入：

- `challenge_mode`：`js-challenge` 或 `captcha`。
- `challenge_result`：`issued`、`passed`、`failed`。
- `bot_result`：如 `captcha-issued`、`captcha-passed`、`captcha-failed`、`behavior-pass`、`search-engine-bypass`、`device-mismatch`。
- `bot_reason`：有限长度原因说明。
- `device_signal`：`matched`、`mismatch` 或空值。

日志不得保存原始 cookie、captcha 答案、签名密钥、Authorization、Cookie 或完整请求体。
