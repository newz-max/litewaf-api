# LiteWaf Functional Requirements and Iteration Roadmap

> Language / 语言: [中文](../功能需求与迭代规划.md) | [English](roadmap.md)

This roadmap records LiteWaf's functional scope and staged delivery plan. The project direction is open-source, lightweight, and fast to deploy, with Debian 12 minimal + Docker Compose as the recommended baseline and mainstream Linux + Docker Compose compatibility.

Planning principles:

- Build the minimum useful protection loop first, then expand detection capability.
- Keep the data plane performant, stable, and rollback-friendly.
- Keep the control plane configurable, auditable, and operable.
- Do not use mock business data in the frontend; show empty/loading/error states when APIs are not connected.
- Keep production installation based on prebuilt images and Docker Compose instead of host-side builds.

The Chinese stage table in the counterpart document is the authoritative progress record for historical phases. For concrete operating steps, prefer [README](../../README.en.md), [Operator guide](usage.md), [API reference](api.md), and [Debian 12 deployment guide](debian12-deployment.md).
