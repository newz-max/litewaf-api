## 1. Documentation Foundation

- [x] 1.1 Add or update the root `README.md` with project positioning, architecture summary, quick-start entry points, module layout, and links to detailed docs.
- [x] 1.2 Create a quick-start document for Debian 12 minimal and compatible Linux + Docker Compose hosts, including prerequisites, `.env` setup, startup, login, publish, gateway smoke test, and shutdown.
- [x] 1.3 Create architecture documentation covering dashboard, API, PostgreSQL, Redis, gateway, generated config, logs, metrics, and deployment boundaries.
- [x] 1.4 Create API documentation for `/api/v1` authentication, common response/error behavior, and major endpoint groups with representative examples.
- [x] 1.5 Create a rule authoring guide covering supported targets, expressions, actions, scoring, policy thresholds, normalization, body/upload inspection, access lists, rate limits, and limitations.
- [x] 1.6 Add contribution and security-sensitive configuration guidance covering repo boundaries, local checks, commit expectations, generated files, secrets, and rule contribution review.
- [x] 1.7 Document the future community rule-pack direction, including metadata, versioning, compatibility, review expectations, and no arbitrary third-party code execution in this stage.

## 2. Default Rule Set

- [x] 2.1 Add a versioned default rule set source for baseline SQLi, XSS, RCE-like, and CC/rate-limit oriented protections using fields supported by the existing rule model.
- [x] 2.2 Implement or update the backend seed/import path so default rules are loaded as real managed rules visible through the rule API and dashboard.
- [x] 2.3 Make default rule seeding idempotent by stable rule identifiers, avoiding duplicate rows across repeated startup or seed runs.
- [x] 2.4 Ensure default rules can be bound to policies and published through the existing gateway configuration pipeline without gateway-only hidden behavior.
- [x] 2.5 Add or update backend tests covering default rule availability, idempotent seeding, validation, and publish inclusion.

## 3. Validation Examples

- [x] 3.1 Add a lightweight example upstream service or static documented equivalent that returns deterministic diagnostics for normal proxy validation.
- [x] 3.2 Add local-only validation samples for normal pass-through, SQLi, XSS, RCE-like, rate-limit/CC, body inspection, upload metadata, access-list behavior, and observability checks where currently supported.
- [x] 3.3 Document expected HTTP status, response shape, WAF event/log observation, and dashboard observation for each validation sample.
- [x] 3.4 Keep attack samples narrowly scoped to local validation against a user-owned LiteWaf instance.

## 4. Compose And Deployment Wiring

- [x] 4.1 Add an opt-in development or validation Compose override/profile for the example upstream without changing production Compose defaults.
- [x] 4.2 Update MVP and quick-start docs so users can route a test Host through the gateway to the example upstream.
- [x] 4.3 Verify production deployment files do not start validation-only upstream services or sample workloads unless explicitly enabled.
- [x] 4.4 Update existing deployment documentation where needed to distinguish quick-start validation from production installation.

## 5. Verification And Project Tracking

- [x] 5.1 Run backend tests for the default rule seed/import and publish path.
- [x] 5.2 Run frontend build if documentation or displayed default-rule behavior changes touch dashboard code.
- [x] 5.3 Run any available local validation scripts; if Docker/OpenResty is unavailable, document the exact skipped end-to-end checks and why.
- [x] 5.4 Update `doc/功能需求与迭代规划.md` to reflect completed Stage 6 items and remaining ecosystem follow-ups.
- [x] 5.5 Run `openspec status --change stage6-open-source-ecosystem` and confirm the change remains ready for implementation or archival workflow.
