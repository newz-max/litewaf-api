# LiteWaf MVP 防护闭环验证

本文档说明如何在 Debian 12 minimal 或其他主流 Linux + Docker Compose 环境中启动第 1 阶段 MVP，并验证站点、规则、策略、发布和 OpenResty 网关拦截闭环。

## 本地开发启动

```bash
cd deploy
docker compose up -d --build
```

本地开发 Compose 默认包含验证 upstream。生产 Compose 不启动验证 upstream；如需在生产 Compose 文件基础上做本地验证，请显式启用 override：

```bash
cd deploy
docker compose -f docker-compose.prod.yml -f docker-compose.validation.yml --profile validation up -d
```

生产部署不要在目标宿主机现场构建镜像。可使用通用 PowerShell 部署脚本上传公开部署文件，并在服务器上拉取预构建镜像：

```powershell
.\deploy\deploy.ps1 -HostName user@your-server
```

也可以手动将 `deploy/docker-compose.prod.yml`、`deploy/.env.example` 和 `deploy/litewafctl.sh` 上传到服务器后执行：

```bash
cd /opt/litewaf/current
./litewafctl.sh validate
./litewafctl.sh install
```

默认端口：

- Dashboard: `http://localhost:18080`
- Gateway: `http://localhost:18081`
- API: 通过 Dashboard 容器反代 `/api/`，容器内服务名为 `waf-api:8080`

## 创建 MVP 配置

登录并保存 token：

```bash
curl -X POST http://localhost:18080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123456"}'

export LITEWAF_TOKEN="<token>"
```

创建站点：

```bash
curl -X POST http://localhost:18080/api/v1/sites \
  -H "Authorization: Bearer $LITEWAF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Example",
    "host": "example.local",
    "upstream": "http://upstream",
    "mode": "protect",
    "enabled": true
  }'
```

查看默认规则：

```bash
curl -H "Authorization: Bearer $LITEWAF_TOKEN" \
  http://localhost:18080/api/v1/rules
```

创建策略。下面示例假设站点 ID 为 `1`，并绑定初始化创建的 LiteWaf 默认规则 `1`、`2`、`3` 和 `4`：

```bash
curl -X POST http://localhost:18080/api/v1/policies \
  -H "Authorization: Bearer $LITEWAF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Example Policy",
    "risk_threshold": 100,
    "default_action": "block",
    "enabled": true,
    "site_ids": [1],
    "normalization_enabled": true,
    "rule_ids": [1, 2, 3, 4]
  }'
```

发布网关配置：

```bash
curl -X POST http://localhost:18080/api/v1/releases \
  -H "Authorization: Bearer $LITEWAF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operator":"admin","note":"mvp verification"}'
```

## 验证代理与阻断

正常代理请求：

```bash
curl -i -H "Host: example.local" http://localhost:18081/
```

预期返回 `200`，响应体来自示例 upstream 服务。

SQLi 阻断请求：

```bash
curl -i -H "Host: example.local" "http://localhost:18081/?q=union%20select"
```

预期返回 `403`，网关 stdout 输出 JSON 格式的 `waf_event` 和 `access_log` 日志。

XSS 阻断请求：

```bash
curl -i -H "Host: example.local" "http://localhost:18081/?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

RCE-like 阻断请求：

```bash
curl -i -H "Host: example.local" "http://localhost:18081/?cmd=%3Bcat%20/etc/passwd"
```

更多样例维护在 `examples/validation/`。

未知 Host：

```bash
curl -i -H "Host: unknown.local" http://localhost:18081/
```

预期返回 `404`，避免代理到任意上游。

## 常用检查

```bash
docker compose ps
docker compose logs -f waf-api
docker compose logs -f gateway
docker compose down
```

如需清空数据：

```bash
docker compose down -v
```
