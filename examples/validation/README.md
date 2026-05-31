# LiteWaf 本地验证样例

这些样例只用于验证你自己本地启动的 LiteWaf 实例。默认假设：

- Dashboard/API: `http://localhost:18080`
- Gateway: `http://localhost:18081`
- Host: `example.local`
- 验证上游：`deploy/upstream/default.conf`

先按 [快速开始](../../doc/快速开始.md) 创建站点、策略并发布默认规则。

## 一键脚本

PowerShell：

```powershell
.\examples\validation\run-samples.ps1
```

Bash：

```bash
bash examples/validation/run-samples.sh
```

## 样例和预期

| 场景 | 请求 | 预期 |
| --- | --- | --- |
| 正常代理 | `GET /echo` | HTTP `200`，响应来自 `litewaf-validation-upstream` |
| SQLi | `/?q=union select` | HTTP `403`，攻击日志出现规则命中 |
| XSS | `/?q=<script>alert(1)</script>` | HTTP `403` |
| RCE-like | `/?cmd=;cat /etc/passwd` | HTTP `403` |
| 归一化路径 | `/%252e%252e/etc/passwd` | 启用归一化策略后预期 HTTP `403` |
| JSON Body | `POST /api/login` 携带 `<script>` | 策略启用 Body 检测并绑定 Body 规则后命中 |
| 上传元数据 | 上传 `shell.php` | 策略启用上传检测并绑定上传规则后命中 |
| 限流 | 多次请求同一 URI | 配置限流后超过阈值返回限流或封禁响应 |

## 查看结果

```bash
cd deploy
docker compose logs -f gateway
```

Dashboard 中可查看：

- 攻击日志
- 访问日志
- 仪表盘汇总

## 范围说明

样例 payload 只用于本地验证 WAF 行为，不应用于测试未授权系统。生产环境启用阻断前，请先结合业务流量观察误报。
