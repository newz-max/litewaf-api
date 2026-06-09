# LiteWaf Contribution Guide

> Language / 语言: [中文](../贡献指南.md) | [English](contributing.md)

Thank you for contributing to LiteWaf. The project direction is open-source, lightweight, and fast to deploy. Contributions should follow that direction: focused changes, real validation, and no unnecessary heavy dependencies.

Repository boundaries:

```text
.                         current repository, Go control-plane API
deploy                    Compose files and deployment scripts
doc                       public documentation
rules                     default rule set
examples                  validation examples
../../openspec            workspace-level specs and change workflow
litewaf-dashboard         companion Vue 3 + Naive UI dashboard repository
litewaf-gateway           companion OpenResty gateway repository
```

Local checks:

```bash
go test ./...
```

Dashboard and Gateway checks live in their companion repositories:

```bash
npm install
npm run build
```

```powershell
.\scripts\smoke.ps1 -Gateway http://localhost:18081 -HostHeader example.local
```

Contribution rules: keep commits focused, do not commit `node_modules/`, `dist/`, logs, `.env`, secrets, backup packages, or production connection strings, and update documentation plus validation notes when changing API behavior, rule fields, deployment scripts, gateway configuration, or user-visible workflows. Future public Markdown under `codes/` should include bilingual Chinese and English coverage or an explicit task to add the missing language before completion.
