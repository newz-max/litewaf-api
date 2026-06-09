# LiteWaf

> Language / 语言: [中文](README.md) | [English](README.en.md)

LiteWaf is an open-source, lightweight, fast-to-deploy OpenResty WAF. The data plane is OpenResty + LuaJIT, the control plane is a Go standard-library API, the dashboard is Vue 3 + TypeScript + Vite + Naive UI, and the default production baseline is Debian 12 minimal with Docker Compose.

LiteWaf is split across three repositories:

- `litewaf-api`: Go control plane, deployment assets, default rules, examples, and the authoritative public documentation.
- `litewaf-dashboard`: Vue 3 dashboard for operators.
- `litewaf-gateway`: OpenResty data-plane gateway that enforces published configuration.

Start here:

- [Online documentation site](https://newz-max.github.io/litewaf-docs/)
- [Documentation index](doc/en/index.md)
- [Operator guide](doc/en/usage.md)
- [Architecture guide](doc/en/architecture.md)
- [API reference](doc/en/api.md)
- [Rule authoring guide](doc/en/rule-authoring.md)
- [Contribution guide](doc/en/contributing.md)
- [Debian 12 minimal deployment guide](doc/en/debian12-deployment.md)

Quick start on a Linux host with Docker Engine and Docker Compose v2:

```bash
bash -c "$(curl -fSL https://raw.githubusercontent.com/newz-max/litewaf-api/master/deploy/manager.sh)"
```

If GitHub access is unstable, use the Gitee entry:

```bash
bash -c "$(curl -fSL https://gitee.com/old_records/litewaf-api/raw/master/deploy/manager.sh)"
```

The installer downloads the production Compose files into `/opt/litewaf`, creates `.env`, replaces weak first-run secrets, pulls prebuilt images, and waits for service health. The dashboard defaults to `http://SERVER_IP:18080`; read generated credentials from `.env`. Creating or editing sites, rules, policies, IP lists, access lists, rate limits, or protection modules does not affect gateway traffic until a new release is published.
