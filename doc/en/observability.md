# LiteWaf Logs and Observability Guide

> Language / 语言: [中文](../日志与可观测验证.md) | [English](observability.md)

This guide validates LiteWaf logging and observability. The default implementation is lightweight: the Gateway writes JSON logs to stdout and, when `LITEWAF_INGESTION_URL` plus `LITEWAF_INGESTION_TOKEN` are configured, reports access logs and WAF events to the API on a best-effort basis. The API stores logs in memory or PostgreSQL depending on runtime configuration.

Key checks:

- Configure `GATEWAY_INGESTION_TOKEN`, `LITEWAF_INGESTION_URL`, metrics flags, sensitive header filtering, and value length limits.
- Generate normal proxied traffic and expected blocked/observed WAF traffic through the Gateway.
- Query access logs, attack logs, blocked/rejected records, observability summaries, protection overview, metrics, and dynamic-ban endpoints.
- Verify that sensitive values such as request bodies, Cookie, Authorization, dynamic tokens, captcha answers, signing secrets, and unbounded match values are not logged.
- For real client IP and GeoIP issues, validate trusted proxy CIDRs, forwarded headers, and access-log `client_ip` before interpreting country/region/city reports.
