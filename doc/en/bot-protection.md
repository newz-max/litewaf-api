# LiteWaf Bot Protection Guide

> Language / 语言: [中文](../Bot防护使用指南.md) | [English](bot-protection.md)

Bot protection adds lightweight verification in front of sensitive paths. The implementation is local: the Gateway does not call the control plane on the request hot path and does not depend on a third-party captcha service.

Supported capabilities:

- `js-challenge`: issue a locally signed cookie and allow requests during the verification TTL.
- `captcha`: issue a local arithmetic captcha and write a signed cookie after success.
- Behavior scoring: calculate a lightweight 0-100 score from request signals such as User-Agent, Accept, and Accept-Language.
- Device signal binding: bind pass tokens to coarse User-Agent / Accept-Language derived signals without storing raw signals.
- Search-engine bypass: bypass by known search-engine User-Agent and log `bot_result=search-engine-bypass`.
- Failure message and privacy notice: show local challenge guidance to users.

Bot rules must be published before gateway enforcement changes. Current scope excludes third-party captcha services, reverse-DNS search-engine verification, long-term device fingerprinting, dynamic tokens, and waiting-room behavior.
