# LiteWaf Documentation Index

> Language / 语言: [中文](../文档索引.md) | [English](index.md)

This is the public documentation entry point for operators, integrators, rule authors, and contributors. Current user-facing guidance is maintained under `codes/litewaf-api/doc/`; workspace-root `doc/` and `openspec/` are internal planning and change-tracking materials, not first-run or day-to-day operating guides.

Recommended English reading order:

| Scenario | Authoritative document | Purpose |
| --- | --- | --- |
| First deployment and startup | [README quick start](../../README.en.md) | Install, service addresses, health checks, and first validation |
| Day-to-day operation | [Operator guide](usage.md) | Create protected applications, configure protection, publish, validate, inspect logs, roll back, and troubleshoot |
| Management API integration | [API reference](api.md) | `/api/v1` endpoints, authentication, publish/rollback, and resource fields |
| System boundaries | [Architecture guide](architecture.md) | Control plane, Dashboard, Gateway, storage, and publish flow |
| Production deployment | [Debian 12 deployment guide](debian12-deployment.md) | Host preparation, installer, backup/restore, upgrade, and rollback |
| Rule authoring | [Rule authoring guide](rule-authoring.md) | Rule fields, targets, actions, scoring, and default rules |
| Logs and observability | [Logs and observability guide](observability.md) | Access logs, WAF events, real client IP, GeoIP, summaries, and metrics |
| Community rule ecosystem | [Community rule package guide](community-rules.md) | Catalogs, trust, import, export, and contribution workflows |
| Code or rule contribution | [Contribution guide](contributing.md) | Repository boundaries, checks, commits, and documentation maintenance |
