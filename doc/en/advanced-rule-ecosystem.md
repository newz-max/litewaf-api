# Advanced Rule Ecosystem Guide

> Language / 语言: [中文](../高级规则生态使用指南.md) | [English](advanced-rule-ecosystem.md)

The advanced rule ecosystem connects local rule package preview, signature status, source tracking, and rule testing into a safe review loop. The first version supports local JSON rule packages only and does not automatically fetch remote rule sources.

Rule packages are JSON artifacts with package metadata, defaults, and rule entries. Preview validates compatibility, signatures, invalid rules, skipped rules, warnings, and source metadata without activating rules. Import creates or updates rules deterministically by `package_id + package_rule_id`; imported executable rules still require publishing before the Gateway enforces them.

Security boundary: signatures and trust state are control-plane metadata and publish-preview warnings. The Gateway enforces only published executable rules and never downloads packages, verifies signatures, or runs third-party code on the request path.
