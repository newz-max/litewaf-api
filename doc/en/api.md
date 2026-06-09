# LiteWaf API Reference

> Language / 语言: [中文](../API文档.md) | [English](api.md)

LiteWaf management APIs use the `/api/v1` prefix by default. In production, expose them only through a protected management entry point; do not publish the API or Dashboard directly to the public internet.

General conventions:

- Request and response payloads are JSON.
- Non-login endpoints require `Authorization: Bearer <token>`.
- Gateway log ingestion and Gateway-only synchronization endpoints use `Authorization: Bearer <gateway-token>`.
- Time fields use RFC3339 or database-returned timestamp formats.
- List endpoints return empty arrays when no data exists and never return mock data.

Main API groups:

| Group | Purpose |
| --- | --- |
| Login | Get the Bearer token and user/role information |
| Applications | Manage protected applications, hosts, listeners, certificates, upstreams, mode, and enabled state |
| Certificates | Upload, validate, list, inspect, and delete certificate metadata without returning private keys |
| Rules and policies | Manage executable rules, managed attack metadata, application bindings, thresholds, and advanced inspection settings |
| Releases | Preview, publish, and roll back gateway configuration versions |
| IP access lists | Manage standalone source IP/CIDR allow and block lists; legacy `/api/v1/access-lists` is removed |
| Protection modules | Manage access control, upload protection, Bot verification, dynamic protection, CC protection, and attack protection |
| Rule ecosystem | Preview/import packages, manage catalogs, trust keys, providers, contribution export, subscriptions, review queues, and false-positive feedback |
| Logs and observability | Query access logs, blocked/rejected records, WAF events, summaries, dynamic bans, ingestion endpoints, audit logs, version, and metrics |

Publish boundary: creating, updating, deleting, enabling, or disabling applications, rules, policies, IP lists, access-control rules, rate limits, and module rules changes only control-plane data. The Gateway enforces those changes only after `POST /api/v1/releases` publishes a new version.
