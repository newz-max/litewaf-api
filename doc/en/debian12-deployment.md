# LiteWaf Debian 12 minimal Deployment Guide

> Language / 语言: [中文](../Debian12部署说明.md) | [English](debian12-deployment.md)

LiteWaf recommends Debian 12 minimal as the default host baseline, but the deployment design is compatible with mainstream Linux distributions that provide Docker Engine, Docker Compose v2, required network ports, and persistent disks.

The production installer stays lightweight: it checks the environment, downloads Compose files, creates `.env`, pulls prebuilt images, and starts containers. It does not build Go, frontend assets, OpenResty, or production images on the host.

Recommended host baseline:

```text
OS: Debian 12 minimal or a compatible mainstream Linux distribution
Runtime: Docker Engine
Compose: Docker Compose v2
Network: ports declared by .env, Dashboard 18080 by default, Gateway 80/443 or application listener ports
Disk: persistent directories for logs, database data, and published gateway configuration
```

First install:

```bash
bash -c "$(curl -fSL https://raw.githubusercontent.com/newz-max/litewaf-api/master/deploy/manager.sh)"
```

If the default Dashboard port is occupied:

```bash
LITEWAF_DASHBOARD_PORT=18082 \
bash -c "$(curl -fSL https://raw.githubusercontent.com/newz-max/litewaf-api/master/deploy/manager.sh)"
```

Use `/opt/litewaf` and `litewafctl.sh` for production operations:

```bash
cd /opt/litewaf
sudo ./litewafctl.sh health
sudo ./litewafctl.sh diagnose
sudo ./litewafctl.sh backup
sudo ./litewafctl.sh upgrade v1.0.1
sudo ./litewafctl.sh rollback
```

Security notes: replace generated secrets only through protected `.env` management, do not expose the management API or Dashboard directly to the public internet, keep `API_LOOPBACK_PORT` bound to loopback, and configure trusted real-IP CIDRs only for immediate trusted proxies. Do not set `LITEWAF_REAL_IP_TRUSTED_CIDRS` to `0.0.0.0/0` or `::/0`.
