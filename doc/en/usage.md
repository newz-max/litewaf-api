# LiteWaf Operator Guide

> Language / 语言: [中文](../使用说明.md) | [English](usage.md)

This operator guide explains the full workflow from creating a protected application to making the OpenResty Gateway enforce it. The key rule is that creating or editing applications, listeners, certificates, rules, policies, IP lists, access-control rules, rate limits, and protection modules only updates control-plane data. The Gateway keeps using the previous active configuration until a new release is published.

Default entry points:

| Service | Address | Notes |
| --- | --- | --- |
| Dashboard | `http://SERVER_IP:18080` | Operator UI |
| Gateway | The listener ports published by protected applications | WAF entry point; production defaults to direct host-network listeners |
| API | Dashboard `/api/` reverse proxy | Management API |

Standard rollout:

1. Log in to the Dashboard and create a protected application with name, host, listener port, protocol, certificate, upstream, mode, and enabled state.
2. Configure protection policies, default rules, or module rules such as CC protection, attack protection, IP access lists, access control, upload protection, Bot verification, dynamic protection, or advanced rule packages.
3. Open release records and publish a new version. The preview shows applications, listeners, certificate risks, rules, policies, module summaries, compatibility diagnostics, and risk warnings before the release is written.
4. Point the application domain to the Gateway host, then validate normal proxied traffic and at least one expected blocked or observed request through the application Host, listener port, and protocol.
5. Check attack logs, access logs, observability summaries, and audit logs to confirm that gateway behavior, release version, and operator actions match.

Important publish boundary: if you only create an application or change rules without publishing, the Gateway still uses the previous active config. If traffic does not reach the Gateway Host/port/protocol, the Dashboard will not show matching access logs.

Validation examples use the same canonical commands shown below in the Chinese section. Replace `<token>`, Host, ports, and upstreams with your environment values. Empty application, log, release, or table data after first install is normal; LiteWaf returns empty arrays or UI empty states instead of mock business rows.
