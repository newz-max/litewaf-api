## Why

LiteWaf already has the core protection, management, observability, and production deployment loops in place, but new users and external contributors still need a clearer path from first install to validating real WAF behavior. The next stage should turn the existing implementation into an easier open-source project to try, understand, extend, and contribute to without weakening the lightweight deployment goal.

## What Changes

- Add a quick-start experience for Debian 12 minimal and compatible Linux + Docker Compose environments, with a concise 10-minute path from environment check to dashboard login and gateway smoke test.
- Add architecture and API documentation that explains the control plane, dashboard, gateway, persistence, logging, metrics, and published configuration flow.
- Add a rule authoring guide covering rule fields, match targets, actions, scoring, policy behavior, and safe examples for SQLi, XSS, RCE, CC, body, upload, and normalized targets.
- Add contribution documentation covering local development, repository boundaries, branch/commit/test expectations, security-sensitive configuration, and how to submit rules or docs.
- Add an example upstream service and attack sample commands so users can validate proxying, blocking, logging, rate limiting, and common detection scenarios locally.
- Add a versioned default rule set source that can seed baseline SQLi, XSS, RCE, and CC protections without relying on dashboard mock data.
- Document a lightweight future plugin extension model for community rule packs without implementing a heavy plugin runtime in this stage.

## Capabilities

### New Capabilities

- `open-source-documentation`: User-facing documentation for quick start, architecture, API reference, rule authoring, contribution, and ecosystem guidance.
- `waf-validation-examples`: Example upstream service and verification samples for local WAF behavior validation.
- `default-rule-set`: Versioned baseline rules that can be loaded as real seed data and published through the existing rule/policy/config pipeline.

### Modified Capabilities

- `rule-management`: Existing rule management behavior must support default baseline rules as real managed rules, not mock dashboard data.
- `mvp-compose-deployment`: Existing Compose-based deployment must include or document the example upstream validation path without disrupting production deployment defaults.

## Impact

- Documentation under `doc/`, root project guidance such as `README.md`, and contribution/security guidance files.
- Example assets under an `examples/` or similarly lightweight directory, including an upstream service and attack/request samples.
- Backend seed data or import path for default rules in `codes/litewaf-api`, plus any related tests.
- Compose or development configuration for wiring the example upstream into local validation only.
- No breaking API changes are expected; existing production deployment and gateway behavior should remain compatible.
