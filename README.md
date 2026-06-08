# LiteWaf

LiteWaf 是一个以源码开放、轻便、快速部署为目标的 OpenResty WAF 项目。数据面使用 OpenResty + LuaJIT，控制面使用 Go 标准库，后台管理使用 Vue 3 + TypeScript + Vite + Naive UI，默认推荐 Debian 12 minimal + Docker Compose 部署。

## 当前能力

- 站点、规则、策略、发布记录管理。
- 登录、Bearer Token 鉴权、角色权限和审计日志。
- 黑白名单、限流、发布预览和历史版本回滚。
- OpenResty 网关按发布配置执行代理、名单、限流、规则匹配、评分阈值、请求体和上传元数据检测。
- 访问日志、WAF 事件、观测汇总和基础 Prometheus 指标。
- 生产 Compose、环境变量模板、健康检查、备份、恢复、升级和回滚脚本。
- 版本化默认规则集和本地验证样例。

## 快速开始

本节面向第一次部署 LiteWaf 的用户，目标是在 Debian 12 minimal 或其他已安装 Docker Engine / Docker Compose v2 的 Linux 服务器上，直接拉取预构建镜像并启动生产栈。

### 前置条件

- 服务器已安装 Docker Engine。
- Docker Compose v2 可用，`docker compose version` 能正常输出。
- 本机端口 `80`、`443`、后台端口（默认 `18080`，或通过 `LITEWAF_DASHBOARD_PORT` 指定）和 `18081` 未被占用。后续在后台发布的自定义应用监听端口也必须未被占用。
- 当前用户可以执行 Docker 命令；若不是 root，请保留下面命令中的 `sudo`。

### 一行部署

在服务器上复制执行：

```bash
bash -c "$(curl -fSL https://raw.githubusercontent.com/newz-max/litewaf-api/master/deploy/manager.sh)"
```

安装入口会下载 `docker-compose.prod.yml`、`.env.example` 和 `litewafctl.sh` 到 `/opt/litewaf`，生成 `.env`，拉取预构建镜像并等待服务健康。安装过程会输出带时间戳的阶段进度，长时间运行的安装和健康检查步骤会定期输出心跳。默认镜像前缀为 `mmxiaozhi`，默认标签为 `latest`。

如果服务器访问 GitHub 不稳定，可使用 Gitee 入口：

```bash
bash -c "$(curl -fSL https://gitee.com/old_records/litewaf-api/raw/master/deploy/manager.sh)"
```

如需指定安装目录、镜像仓库或版本标签，可通过环境变量覆盖：

```bash
LITEWAF_INSTALL_DIR=/opt/litewaf \
LITEWAF_IMAGE_PREFIX=mmxiaozhi \
LITEWAF_IMAGE_TAG=latest \
bash -c "$(curl -fSL https://raw.githubusercontent.com/newz-max/litewaf-api/master/deploy/manager.sh)"
```

如果默认后台端口 `18080` 已被占用，可在一行部署时指定新的后台端口：

```bash
LITEWAF_DASHBOARD_PORT=18082 \
bash -c "$(curl -fSL https://raw.githubusercontent.com/newz-max/litewaf-api/master/deploy/manager.sh)"
```

安装脚本会自动检查 Docker、Compose、端口、生产密钥和 Compose 配置；首次安装会把 `.env` 中的弱默认值替换为随机密钥。已存在 `.env` 时会保留原配置，只有显式传入 `LITEWAF_IMAGE_PREFIX`、`LITEWAF_IMAGE_TAG` 或 `LITEWAF_DASHBOARD_PORT` 时才会改写对应配置。

### 升级

已安装 LiteWaf 的服务器可在安装目录中直接升级到最新镜像：

```bash
cd /opt/litewaf
sudo ./litewafctl.sh upgrade latest
```

如需升级到指定版本，把 `latest` 替换为目标镜像标签：

```bash
cd /opt/litewaf
sudo ./litewafctl.sh upgrade v1.0.1
```

### 手动部署

如果需要离线排障或手动检查下载内容，也可以按下面的方式执行：

```bash
sudo mkdir -p /opt/litewaf
cd /opt/litewaf

BASE_URL="https://raw.githubusercontent.com/newz-max/litewaf-api/master/deploy"

sudo curl -fsSLo docker-compose.prod.yml "$BASE_URL/docker-compose.prod.yml"
sudo curl -fsSLo .env.example "$BASE_URL/.env.example"
sudo curl -fsSLo litewafctl.sh "$BASE_URL/litewafctl.sh"

sudo chmod +x litewafctl.sh
sudo cp -n .env.example .env

sudo sed -i \
  -e 's|^LITEWAF_IMAGE_PREFIX=.*|LITEWAF_IMAGE_PREFIX=mmxiaozhi|' \
  -e 's|^LITEWAF_IMAGE_TAG=.*|LITEWAF_IMAGE_TAG=latest|' \
  .env

sudo ./litewafctl.sh install
sudo ./litewafctl.sh health
```

### 访问服务

查看服务状态：

```bash
cd /opt/litewaf
sudo docker compose -p litewaf --env-file .env -f docker-compose.prod.yml ps
```

查看访问地址和后台账号：

```bash
cd /opt/litewaf
sudo grep -E '^(DASHBOARD_PORT|GATEWAY_LISTENER_MODE|GATEWAY_BRIDGE_PORT_RANGE|API_LOOPBACK_PORT|LITEWAF_ADMIN_USERNAME|LITEWAF_ADMIN_PASSWORD)=' .env
```

默认入口：

| 服务 | 地址 | 说明 |
| --- | --- | --- |
| Dashboard | `http://服务器IP:18080` | 后台管理页面，端口可通过 `LITEWAF_DASHBOARD_PORT` 自定义 |
| Gateway | 应用发布的监听端口 | OpenResty WAF 网关，默认 host-network 直接监听宿主机端口 |
| API | Dashboard `/api/` 反代 | 控制面 API |
| PostgreSQL | Compose 内部网络 | 配置、用户、日志存储 |
| Redis | Compose 内部网络 | 轻量运行状态 |

生产 Compose 默认使用 `GATEWAY_LISTENER_MODE=host-network`。发布防护应用后，Gateway 会按应用里的监听配置直接绑定宿主机端口，例如 `80/http`、`443/https` 或 `9981/http`；HTTPS 监听使用后台上传并绑定的证书文件，不再要求用户额外维护宿主机 Nginx 才能让普通应用端口生效。

如果运行环境不能使用 host network，可显式叠加 `docker-compose.bridge-range.yml`，并把 `.env` 中 `GATEWAY_LISTENER_MODE` 设为 `bridge-range`、`GATEWAY_BRIDGE_PORT_RANGE` 设为已映射端口范围。超出范围的监听会在发布预览或发布时被阻断。

网关健康检查：

```bash
curl -i http://127.0.0.1/healthz
```

### 常用运维命令

```bash
cd /opt/litewaf

sudo ./litewafctl.sh health
sudo ./litewafctl.sh diagnose
sudo ./litewafctl.sh backup
sudo ./litewafctl.sh upgrade latest
sudo ./litewafctl.sh rollback
```

查看日志：

```bash
cd /opt/litewaf
sudo docker compose -p litewaf --env-file .env -f docker-compose.prod.yml logs -f gateway
sudo docker compose -p litewaf --env-file .env -f docker-compose.prod.yml logs -f waf-api
```

停止服务：

```bash
cd /opt/litewaf
sudo docker compose -p litewaf --env-file .env -f docker-compose.prod.yml down
```

清空数据并停止服务：

```bash
cd /opt/litewaf
sudo docker compose -p litewaf --env-file .env -f docker-compose.prod.yml down -v
```

### 首次验证

首次登录 Dashboard 后，按下面顺序完成最小验证：

1. 在“防护应用”创建应用，填写域名、入口监听、协议、证书、上游地址、运行模式和启用状态。
2. 在“规则管理”“策略”或模块页面启用需要验证的规则和策略。
3. 进入“发布记录”，点击“发布新版本”。创建应用、修改监听或修改防护配置后必须发布，网关才会加载新配置。
4. 通过应用的 Host、端口和协议访问 Gateway，验证正常请求可以代理到上游。HTTPS 应用需确认监听已绑定证书。
5. 发送一条预期会被阻断或观察的请求，再到攻击日志、访问日志和观测汇总确认结果。

API 验证时可先预览再发布：

```bash
curl -H "Authorization: Bearer <token>" http://localhost:18080/api/v1/releases/preview
curl -X POST http://localhost:18080/api/v1/releases \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"operator":"admin","note":"first validation"}'
```

正常代理和阻断验证：

```bash
curl -i -H "Host: example.local" http://localhost/
curl -k -i -H "Host: example.local" https://localhost/
curl -i -H "Host: example.local" "http://localhost/?q=union%20select"
```

日常后台操作、发布边界和排障见 [使用说明](doc/使用说明.md)，生产部署和安全加固见 [Debian 12 minimal 部署说明](doc/Debian12部署说明.md)。

## 目录结构

```text
./                   当前仓库，Go 控制面 API
deploy/              Compose、生产脚本和验证 upstream 配置
doc/                 架构、部署、验证和使用文档
rules/               默认规则集
examples/            本地验证样例
../../openspec/       工作区级规格和变更工作流
litewaf-dashboard    配套前端仓库
litewaf-gateway      配套网关仓库
```

## 相关仓库

- 后端与项目文档：[litewaf-api](https://github.com/newz-max/litewaf-api)
- 前端管理台：[litewaf-dashboard](https://github.com/newz-max/litewaf-dashboard)
- OpenResty 数据面网关：[litewaf-gateway](https://github.com/newz-max/litewaf-gateway)

## 文档入口

- [文档索引](doc/文档索引.md)
- [使用说明](doc/使用说明.md)
- [架构说明](doc/架构说明.md)
- [API 文档](doc/API文档.md)
- [规则编写指南](doc/规则编写指南.md)
- [贡献指南](doc/贡献指南.md)
- [规则生态路线](doc/规则生态路线.md)
- [Debian 12 minimal 部署说明](doc/Debian12部署说明.md)

## 开发命令

后端：

```bash
go test ./...
go run ./cmd/litewaf-api
```

前端源码在配套仓库中维护：

```bash
npm install
npm run build
npm run dev
```

网关源码在配套仓库中维护：

```bash
docker build -t litewaf-gateway .
```

## 规则集

默认规则集位于 [rules/default-rules.json](rules/default-rules.json)，控制面启动时会将这些规则作为真实托管规则写入存储。默认规则用于开箱验证和基础防护，不等同于完整托管规则库，生产环境应结合业务流量调优。

## 许可证

本仓库采用 [Apache License 2.0](LICENSE)。你可以按该许可证使用、复制、修改、分发和商业使用本项目。
