## Context

LiteWaf currently supports site routing, rule and policy publishing, access lists, rate limits, rollback, gateway JSON logs, ingestion, and dashboard observability. The gateway enforcement path is intentionally lightweight, but the next protection stage needs to catch common bypasses and abuse patterns that are not well represented by direct query-parameter matching alone.

The implementation must preserve the current deployment posture: OpenResty + LuaJIT for the data plane, Go `net/http` for the control plane, Vue 3 + TypeScript + Naive UI for the dashboard, Docker Compose as the first deployment target, and no mandatory native detection engines in this change.

## Goals / Non-Goals

**Goals:**
- Normalize request inputs before matching so encoded or path-obfuscation payloads are evaluated consistently.
- Support cumulative risk scoring at the policy level while preserving existing `pass`, `log-only`, and `block` rule actions.
- Add guarded body and upload metadata inspection with explicit size and content-type limits.
- Add temporary source IP bans from severe WAF matches, repeated score-threshold blocks, or repeated rate-limit violations.
- Publish advanced settings in a backward-compatible gateway configuration format.
- Preserve sensitive-data constraints in gateway logs and API-stored events.

**Non-Goals:**
- Do not require libinjection, Hyperscan, or other native matching engines.
- Do not implement full antivirus scanning, sandboxing, or deep file-content inspection.
- Do not make request-body inspection globally unlimited or enabled by default for every route.
- Do not replace the existing rule, policy, access-list, rate-limit, publish, or observability APIs.

## Decisions

1. Normalize in the gateway before target extraction.

   The gateway will create bounded normalized views for URI, path, query values, selected headers, and configured body fields before rule evaluation. The original request continues to proxy unchanged unless blocked. This keeps upstream compatibility while giving the WAF a consistent inspection surface. Alternative considered: normalize in the API at publish time, but runtime normalization is required because payload encoding differs per request.

2. Keep scoring additive and policy-scoped.

   Each matched enabled rule contributes its configured score unless its action immediately determines a stronger outcome. The policy publishes a score threshold and threshold action; exceeding that threshold creates a score-based enforcement event. This fits the existing policy model and avoids a separate correlation service. Alternative considered: global scoring across all sites, but per-policy scoring is clearer and safer for multi-site deployments.

3. Make body inspection opt-in and bounded.

   Policies publish allowed content types, path matchers, and maximum inspected bytes. The gateway only reads body data for matching requests and stores summaries rather than full body content. This limits latency and memory risk in the OpenResty hot path. Alternative considered: inspect every request body, but that conflicts with the lightweight gateway goal.

4. Inspect upload metadata before file content.

   Multipart inspection focuses on filename, extension, MIME type, and declared or observed size. Full file content scanning is deferred. This covers common dangerous-upload controls without introducing antivirus dependencies or large buffering requirements.

5. Store temporary bans in gateway shared dictionaries.

   Dynamic bans should be enforced locally before normal WAF evaluation. Ban state is best-effort and local to a gateway instance for this stage; persistent or clustered ban replication can be added later. Alternative considered: call the API on every ban decision, but that would put remote IO on the request path.

6. Extend existing log payloads instead of adding a new event pipeline.

   WAF event logs gain optional fields for normalized target, score, threshold, body/upload metadata, and ban reason. Existing ingestion and query endpoints continue to work while preserving richer event fields for dashboard and audit views.

## Risks / Trade-offs

- Body inspection increases latency and memory pressure -> Keep it opt-in, enforce byte limits, and skip unsupported content types.
- Repeated URL decoding can be abused for CPU cost -> Limit normalization passes and cap inspected string lengths.
- Score thresholds can block legitimate traffic if tuned too aggressively -> Default to conservative thresholds and expose log-only/testing workflows through existing rule actions.
- Local dynamic bans are not cluster-wide -> Document the behavior and keep ban duration explicit; clustered synchronization remains a later enhancement.
- Multipart parsing in Lua can be fragile -> Start with bounded metadata extraction and fail closed only for explicitly invalid or oversized uploads configured to block.
- New log fields can expose sensitive payload fragments -> Store bounded summaries and never persist full request bodies, Authorization, Cookie, or configured sensitive headers.

## Migration Plan

1. Extend API models, validation, storage, and publish serialization with backward-compatible optional fields.
2. Update gateway config loading to apply defaults when advanced fields are absent.
3. Implement gateway normalization, scoring, body/upload inspection, dynamic ban checks, and event extensions behind published settings.
4. Update dashboard forms and observability views to use real API fields without mock data.
5. Update deployment examples and validation docs for shared dictionary sizing and inspection limits.
6. Rollback remains the existing publish rollback path; older published configs without advanced fields must continue to load with defaults.

## Open Questions

- Should policy score thresholds have separate actions for query/header/body/upload matches, or one threshold action per policy for the first implementation?
- Should dynamic bans be configurable only at policy level, or also per individual rule?
- Which body content types should be enabled by default in development seed data, if any?
