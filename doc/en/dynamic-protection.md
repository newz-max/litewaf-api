# LiteWaf Dynamic Protection Guide

> Language / 语言: [中文](../动态防护使用指南.md) | [English](dynamic-protection.md)

This guide covers the first LiteWaf dynamic protection and waiting-room capabilities. The implementation stays lightweight: all gateway decisions use published local configuration and OpenResty shared dictionaries, with no control-plane API or database calls on the request hot path.

Current rule categories:

- Dynamic token: issue and validate short-lived tokens for browser paths such as admin or campaign pages.
- Page mutation: inject controlled markers into small HTML responses for browser-side dynamic signals and future extensions.
- Waiting room: locally admit requests with signed cookies based on configured capacity; overflow requests can retry, be observed, or be blocked.

Rollout guidance: start with narrow paths and `log-only`/observe behavior where possible, publish the configuration, validate token issue/pass/failure or queue behavior through the Gateway, then inspect attack logs, access logs, and dynamic-ban state. Manual unban synchronization uses a polling feed outside the request hot path and can take one interval to affect enforcement.
