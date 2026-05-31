# LiteWaf Debian 12 minimal 部署说明

## 部署目标

LiteWaf 推荐以 Debian 12 minimal 作为默认宿主机基线，但项目不依赖 Debian 专有宿主机能力。部署目标是兼容主流 Linux 发行版，只要求宿主机提供 Docker Engine、Docker Compose v2、网络端口和持久化磁盘。

安装速度优先通过“预构建镜像 + Docker Compose 启动”保证。生产安装脚本只做环境检查、下载 compose、生成 `.env`、拉取镜像和启动容器，不在宿主机现场编译 Go、前端或 OpenResty。

## 基础环境

推荐宿主机环境：

```text
OS: Debian 12 minimal，兼容主流 Linux 发行版
Runtime: Docker Engine
Compose: Docker Compose v2
Network: 按 `.env` 开放必要端口，默认 Dashboard 18080、Gateway 18081
Disk: 为日志、数据库和规则配置预留独立目录
```

## 系统准备

生产环境建议提前确认：

- Docker Engine 已安装并设置开机自启动。
- Docker Compose v2 可用。
- 系统时区已设置。
- 防火墙只开放必要端口。
- `ulimit nofile` 已调高。
- 日志轮转策略已配置。
- 数据目录和备份目录已规划。

## 安装脚本策略

生产安装脚本应保持轻量，参考成熟 WAF 项目的快速安装模型：

- 检查 CPU 架构、Docker、Compose、端口、磁盘空间、ulimit、防火墙和 SELinux/ufw/firewalld 状态。
- 未安装 Docker 时给出安装指引或可选安装流程。
- 创建安装目录，生成 `.env` 和随机密钥。
- 下载固定版本的 `docker-compose.yml` 和必要辅助脚本。
- 选择可用镜像源后执行 `docker compose pull`。
- 执行 `docker compose up -d --remove-orphans`。
- 等待关键服务 healthcheck 成功并输出访问地址。

生产部署默认使用 `deploy/docker-compose.prod.yml`、`.env.example` 和 `litewafctl.sh`，并在目标服务器拉取预构建镜像。示例 upstream 只用于本地验证，不属于生产默认拓扑。镜像仓库未准备好时，不建议在生产宿主机现场构建；可在 CI 或可信构建机上先发布镜像。

安装脚本不应执行以下操作：

- 在宿主机安装 PostgreSQL、Redis、Node.js、Go 或 OpenResty。
- 在宿主机执行 `npm install`、`npm run build`、`go build` 或 OpenResty/Lua 模块编译。
- 默认现场 `docker build` 生产镜像。开发环境可以保留 build compose，生产环境应拉取已发布镜像。

## 生产运维入口

`deploy/litewafctl.sh` 是生产主机上的统一入口。脚本默认读取当前目录的 `docker-compose.prod.yml` 和 `.env`：

```bash
cd /opt/litewaf/current
./litewafctl.sh validate
./litewafctl.sh install
./litewafctl.sh health
```

`validate` 会检查 Docker、Compose、磁盘可见性、`nofile`、端口占用、弱密钥和 Compose 配置。首次运行会从 `.env.example` 生成 `.env`，并为 `POSTGRES_PASSWORD`、`AUTH_TOKEN_SECRET`、`GATEWAY_INGESTION_TOKEN`、`LITEWAF_ADMIN_PASSWORD` 生成随机值。已有 `.env` 中的非默认值会保留。

生产 `.env` 的关键约定：

```text
APP_ENV=production
LITEWAF_IMAGE_PREFIX=litewaf
LITEWAF_IMAGE_TAG=v1.0.0
METRICS_ENABLED=false
LITEWAF_METRICS_ENABLED=false
```

`LITEWAF_IMAGE_TAG` 建议使用不可变版本标签，不建议生产长期使用 `latest`。

## 备份和恢复

创建备份：

```bash
cd /opt/litewaf/current
./litewafctl.sh backup
```

备份包默认写入 `backups/`，包含：

- PostgreSQL 逻辑备份。
- 当前网关配置。
- `.env`。
- Compose 展开配置。
- `manifest.json`。

备份包包含密钥和数据库内容，应存放在受保护目录，并同步到独立备份介质。

恢复备份：

```bash
cd /opt/litewaf/current
LITEWAF_RESTORE_CONFIRM=yes ./litewafctl.sh restore backups/litewaf-backup-YYYYMMDDTHHMMSSZ.tar.gz
```

恢复会停止当前 Compose 服务，校验备份 manifest，恢复 `.env`、PostgreSQL 数据和网关配置，然后重新启动服务并等待健康检查通过。

## 升级和回滚

升级到指定镜像标签：

```bash
cd /opt/litewaf/current
./litewafctl.sh upgrade v1.0.1
```

升级流程会记录当前镜像标签、创建升级前备份、修改 `LITEWAF_IMAGE_TAG`、拉取镜像、重启服务并等待健康检查。升级状态写入 `state/`。

普通标签回滚：

```bash
cd /opt/litewaf/current
./litewafctl.sh rollback
```

如果失败升级包含不可逆数据库变更，应先使用升级前备份执行 restore，再启动旧版本镜像。

## 服务部署方式

第一阶段推荐使用 Docker Compose 单机部署：

```text
waf-gateway      OpenResty WAF 网关
waf-api          Go 控制面 API
waf-dashboard    Vue + Naive UI 后台
postgres         规则、策略、用户和审计数据
redis            配置热更新和轻量状态同步
```

本地快速开始和 MVP 验证可以使用 `deploy/docker-compose.yml` 中的示例 upstream。若需要在生产 Compose 文件基础上临时验证 upstream 路由，必须显式叠加 `deploy/docker-compose.validation.yml` 和 `validation` profile；生产安装脚本不会默认上传或启动该验证服务。

第二阶段可以加入：

```text
clickhouse       WAF 日志分析
vector           日志采集和转发
prometheus       指标采集
grafana          监控面板
```

## 镜像基线

运行时镜像优先轻量化，但按组件分层取舍：

```text
Go API builder: golang:<version>-bookworm
Go API runtime: debian:12-slim，稳定后可评估 distroless / scratch
Dashboard builder: node:<version>-bookworm
Dashboard runtime: nginx:<version>-alpine
OpenResty runtime: openresty/openresty:<version>-bookworm，验证后提供 alpine-slim 变体
PostgreSQL: postgres:<version>-bookworm
Redis: redis:<version>-alpine
```

OpenResty 网关初期优先使用 Bookworm 系列镜像，降低 Lua/native 模块兼容和排障成本。后续在规则引擎、Lua 依赖和健康检查稳定后，再维护 Alpine 变体。

镜像发布命令维护在 `doc/镜像发布说明.md`。生产安装脚本通过 `LITEWAF_IMAGE_PREFIX` 和 `LITEWAF_IMAGE_TAG` 拉取：

```text
${LITEWAF_IMAGE_PREFIX}/litewaf-api:${LITEWAF_IMAGE_TAG}
${LITEWAF_IMAGE_PREFIX}/litewaf-dashboard:${LITEWAF_IMAGE_TAG}
${LITEWAF_IMAGE_PREFIX}/litewaf-gateway:${LITEWAF_IMAGE_TAG}
```

## 运维建议

- 网关容器保持无状态，规则和策略从控制面同步。
- 数据库、Redis、ClickHouse 必须使用持久化 volume。
- WAF 日志优先输出 JSON 到 stdout，再由日志采集器处理。
- 规则发布必须支持版本号、审计记录和回滚。
- 生产环境不要把管理后台直接暴露到公网，建议加 VPN、堡垒机或反向代理鉴权。
- 生产环境默认关闭 API 和网关指标暴露；如需开启，只允许内网 Prometheus 或带鉴权的反向代理访问。
- Docker daemon 建议配置日志轮转，例如 `max-size=100m`、`max-file=5`，避免长期运行撑满磁盘。
- 高并发场景应结合压测调整宿主机 `nofile`、容器资源限制、OpenResty worker 和 shared dict 大小。
