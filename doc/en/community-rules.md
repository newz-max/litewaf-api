# Community Rule Package and Marketplace Guide

> Language / 语言: [中文](../社区规则包与规则市场说明.md) | [English](community-rules.md)

This guide covers community rule catalogs, remote package preview, trust keys, explicit update review, contribution export, account/subscription sources, contribution push, review queues, and false-positive feedback. These workflows run only in the control-plane API and Dashboard.

Important boundaries:

- Catalog sync and remote preview never create, enable, disable, delete, publish, or modify rules automatically.
- Trust keys affect preview/import/update warnings and decisions, but the Gateway does not evaluate trust metadata at request time.
- Provider credentials are write-only where sensitive; responses return public metadata such as alias, fingerprint, last-four characters, validation time, and status.
- Contribution export includes package JSON, checksum, rule count, and guidance, but not private keys, API tokens, Authorization/Cookie values, raw traffic samples, database connection strings, or deployment secrets.
- The Gateway enforces only published executable rules; it does not poll catalogs, verify signatures, or read exported artifacts on the hot path.
