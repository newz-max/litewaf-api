# LiteWaf Rule Ecosystem Roadmap

> Language / 语言: [中文](../规则生态路线.md) | [English](rule-ecosystem-roadmap.md)

Stage 6 defines a lightweight rule ecosystem direction. It does not implement dynamic third-party code execution and does not introduce a remote plugin marketplace.

Current state:

- Default rules are maintained in `rules/default-rules.json`.
- The API seeds default rules into real rule storage on startup.
- Dashboard and publish flow operate on the same managed rules.
- Local validation examples cover SQLi, XSS, RCE-like payloads, rate limiting, request body, upload metadata, and access-list scenarios.

Future rule packages should remain data artifacts with metadata, compatibility, review status, checksums, optional signatures, and contribution expectations. Executable plugin systems, remote code loading, and arbitrary Lua execution remain out of scope unless a later design explicitly adds them.
