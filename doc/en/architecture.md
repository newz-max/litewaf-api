# LiteWaf Architecture Guide

> Language / 语言: [中文](../架构说明.md) | [English](architecture.md)

LiteWaf is split into a control plane, Dashboard, data-plane Gateway, and storage services. Configuration is maintained in the control plane. A release generates JSON gateway configuration, listener configuration, and certificate files that the Gateway can consume. The Gateway request hot path reads only local configuration and OpenResty shared dictionaries; it does not call a remote database.

Component boundaries:

| Component | Role |
| --- | --- |
| Dashboard | Operator UI for applications, certificates, rules, policies, logs, releases, and system pages |
| API | Management API, authentication, audit, release generation, log ingestion, and observability summaries |
| Gateway | OpenResty multi-listener reverse proxy, TLS entry, WAF checks, rate limiting, logs, and metrics |
| PostgreSQL | Users, applications, certificates, rules, policies, releases, audit, and logs |
| Redis | Lightweight runtime state and future synchronization support |

Publish flow: operators change applications or protection data in the Dashboard/API, preview the release, publish a version, and the API writes the active gateway files. Gateway workers then enforce the new local config. Unknown Host, listener port, or protocol combinations must fail closed instead of proxying to arbitrary upstreams.
