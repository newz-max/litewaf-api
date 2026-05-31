## Context

LiteWaf has already implemented the core WAF control plane, dashboard, OpenResty gateway, observability, production Compose deployment, backup/restore, and upgrade/rollback flows. The remaining stage is less about adding a large runtime subsystem and more about making the project usable by people who are not already inside the implementation: first-time operators, contributors, and rule authors.

The project constraints remain unchanged: open-source, lightweight, Debian 12 minimal first, Docker Compose oriented, no mock business data in API or dashboard flows, and no heavy framework additions unless a later decision explicitly justifies them.

## Goals / Non-Goals

**Goals:**

- Provide a clear first-run path that gets a user from repository checkout or released files to a working dashboard and gateway validation flow.
- Document the architecture, API surface, rule model, contribution process, and rule pack direction in files that can evolve with the project.
- Provide local examples that exercise real gateway behavior with a minimal upstream service and repeatable request samples.
- Introduce a versioned default rule set that seeds real rules through the existing control-plane model and can be published like operator-created rules.
- Keep the stage compatible with production deployment and avoid adding nonessential runtime dependencies.

**Non-Goals:**

- Implement a full rule marketplace, remote plugin registry, dynamic third-party code execution, or paid ecosystem features.
- Replace the existing rule management, publishing, or gateway configuration pipeline.
- Add ClickHouse, Prometheus collection, alerting, libinjection, Hyperscan, or other postponed protection/observability enhancements.
- Make the example upstream service part of the production deployment path.

## Decisions

1. Documentation is source-controlled markdown, not generated from a new docs framework.

   Rationale: The project is still prioritizing fast deployment and low maintenance cost. Markdown under `README.md`, `doc/`, and contributor guidance files is enough for this stage and avoids adding a static-site toolchain.

   Alternatives considered: A documentation site generator would improve navigation later, but it adds build and publish machinery before the project has enough docs volume to justify it.

2. Validation examples live outside production service defaults.

   Rationale: The upstream demo service and attack samples are useful for learning and CI-like smoke checks, but production Compose should stay focused on real API, dashboard, gateway, PostgreSQL, and Redis services. Examples should be opt-in through a sample compose override, profile, script, or documented local command.

   Alternatives considered: Always including the example service in production Compose would make quick starts simpler, but it pollutes production topology and may confuse operators.

3. Default rules are represented as versioned seed data compatible with the existing rule model.

   Rationale: Operators should see and publish default SQLi, XSS, RCE, and CC baseline protections as real managed rules. This preserves auditability and avoids hidden gateway-only behavior.

   Alternatives considered: Hard-coding default rules inside the gateway would reduce backend work, but would split rule sources and make dashboard state misleading.

4. Community rule packs are documented as a future importable artifact shape, not as executable plugins.

   Rationale: A WAF plugin model can become security-sensitive quickly. This stage should define the lightweight direction for rule packs, including metadata, version, compatibility, and review expectations, while keeping runtime execution limited to the existing safe rule fields.

   Alternatives considered: Implementing dynamic plugin loading now would make the ecosystem story more ambitious, but it increases security and compatibility risk before the default rules and authoring guide are mature.

5. API documentation starts from the current `/api/v1` management surface and examples rather than introducing OpenAPI generation as a hard dependency.

   Rationale: The API can be documented accurately with grouped endpoints, authentication requirements, request/response examples, and error conventions. OpenAPI generation can be added later if it becomes part of release quality gates.

   Alternatives considered: Hand-authored OpenAPI now would help tooling, but stale schema risk is high unless tests or generation are introduced at the same time.

## Risks / Trade-offs

- Default rules become stale or too noisy -> Keep rules versioned, intentionally small, documented, and testable through examples before expanding coverage.
- Documentation drifts from implementation -> Add tasks to verify documented commands against local builds where possible and keep API examples tied to real endpoints.
- Example attack samples are misunderstood as offensive tooling -> Keep samples narrow, local, and clearly scoped to validating a user-owned LiteWaf instance.
- Plugin language over-promises runtime extensibility -> Document rule pack import conventions as future-facing and avoid promising arbitrary code execution.
- Compose quick-start diverges from production Compose -> Keep example wiring opt-in and document the difference between quick-start validation and production installation.
