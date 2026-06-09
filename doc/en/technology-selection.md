# OpenResty WAF Technology Selection Outline

> Language / 语言: [中文](../技术选型大纲.md) | [English](technology-selection.md)

This document records the technical baseline for LiteWaf: a high-performance WAF system running in Docker with a separated data plane and control plane.

Core decisions:

- Data plane: OpenResty + LuaJIT for low-latency request inspection, blocking, rate limiting, and log output.
- Control plane: Go API for protected applications, certificates, rule/policy management, releases, audit, and observability.
- Dashboard: Vue 3 + TypeScript + Vite + Naive UI.
- Deployment: Docker Compose first, Debian 12 minimal as the recommended host baseline, compatible with mainstream Linux distributions.
- Storage: PostgreSQL for durable configuration/log data and Redis for lightweight runtime state.

The Gateway hot path must not call remote databases. Rules and policies are published ahead of time into local gateway configuration and memory/shared dictionaries. Request-body inspection is opt-in, logs are structured JSON, and rollback is handled through versioned published configuration.
