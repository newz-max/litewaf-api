# LiteWaf API Service Guide

> Language / 语言: [中文](../后端服务说明.md) | [English](api-service.md)

LiteWaf API is the control-plane backend. It manages protected applications, certificates, rules, policies, release/rollback, authentication, audit, log ingestion, and observability queries. The current service is intentionally lightweight and uses the Go standard library HTTP stack.

Run locally:

```bash
go run ./cmd/litewaf-api
```

Health check:

```bash
curl http://localhost:8080/healthz
```

Key environment variables include `APP_ENV`, `HTTP_ADDR`, `DATABASE_URL`, `REDIS_ADDR`, `AUTH_TOKEN_SECRET`, `GATEWAY_INGESTION_TOKEN`, `GATEWAY_CONFIG_PATH`, and GeoIP database paths. Management APIs use the `/api/v1` prefix; list endpoints return empty arrays when no data exists and never return mock rows.
