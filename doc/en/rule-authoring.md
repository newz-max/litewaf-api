# LiteWaf Rule Authoring Guide

> Language / 语言: [中文](../规则编写指南.md) | [English](rule-authoring.md)

LiteWaf rules are managed, audited, and published as control-plane data. They are not hidden gateway-only logic, and the Dashboard must not use mock business rows for rule pages.

Core fields:

- `name`: stable readable rule name.
- `type`: `sqli`, `xss`, `rce`, `path-traversal`, `cc`, `bot`, or `custom`.
- `target`: inspection target such as URI, args, headers, body, or upload metadata.
- `action`: `pass`, `block`, or `log-only`.
- `expression`: the match expression or pattern.
- `score`: contribution to policy threshold decisions.
- `enabled`: whether the rule is included when published.

Authoring guidance: start dangerous or broad rules in `log-only`, bind them through policies or module pages, publish a new release before expecting gateway enforcement, and validate with normal traffic plus at least one expected match. Unsupported/deferred behavior includes arbitrary Lua plugins, remote rule execution on the hot path, libinjection, Hyperscan, and dynamic third-party code execution.
