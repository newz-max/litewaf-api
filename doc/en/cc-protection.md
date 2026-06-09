# LiteWaf CC Protection Guide

> Language / 语言: [中文](../CC防护使用指南.md) | [English](cc-protection.md)

CC protection limits high-frequency access, login brute force, API abuse, 404 scanning, and attack-hit frequency. Rules are managed as `module=cc-protection`, `category=rate-limit` protection rules. Upload protection, Bot verification, captcha, and dynamic protection are handled by their own modules.

Recommended templates include login brute-force limits, API request-rate limits, whole-site baseline CC protection, 404 scan limits, and session-level login limits. Supported counters include `client_ip`, `client_ip_path`, and `global`; actions include `log-only`, `block`, `rate-limit`, and `ban`.

Publish requirement: CC rules must be published before the Gateway updates `protection_rules` and starts counting or enforcing them. Use preview endpoints for matching and risk explanation; preview does not modify rules, publish records, or gateway counters.
