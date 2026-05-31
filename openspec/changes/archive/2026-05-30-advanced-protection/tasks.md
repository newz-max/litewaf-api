## 1. Control Plane Data Model

- [x] 1.1 Extend rule models, validation, storage, and API responses for normalized URI/path/query/header targets, body targets, and upload metadata targets.
- [x] 1.2 Extend policy models, validation, storage, and API responses for score thresholds, threshold action, normalization options, body inspection limits, upload inspection limits, and dynamic-ban settings.
- [x] 1.3 Extend rate-limit models, validation, storage, and API responses for repeated-violation tracking windows, violation thresholds, and temporary ban duration.
- [x] 1.4 Add backward-compatible defaults so existing stored rules, policies, and rate-limit rules continue to read and publish without manual migration.

## 2. Publishing

- [x] 2.1 Update publish validation to reject invalid advanced rule targets, score thresholds, inspection limits, upload limits, normalization limits, and dynamic-ban settings.
- [x] 2.2 Update gateway configuration generation to include advanced rule targets, policy score settings, body/upload inspection settings, normalization settings, and dynamic-ban settings.
- [x] 2.3 Update publish preview summaries to identify changed advanced protection settings.
- [x] 2.4 Add API tests for valid and invalid advanced publish payloads and rollback compatibility with configs that omit advanced fields.

## 3. Gateway Enforcement

- [x] 3.1 Add bounded normalization utilities for URI, path, query values, selected headers, and decoded inspection strings.
- [x] 3.2 Update gateway config loading to apply safe defaults for missing advanced fields.
- [x] 3.3 Extend rule target extraction and matching to evaluate normalized values while proxying the original request unchanged when allowed.
- [x] 3.4 Implement policy-scoped cumulative scoring and threshold actions while preserving immediate `block`, `log-only`, and `pass` behavior.
- [x] 3.5 Implement opt-in body inspection for configured paths and content types with maximum inspected byte limits and oversized-body action handling.
- [x] 3.6 Implement multipart upload metadata inspection for filename, extension, MIME type, and size limits without full file-content scanning.
- [x] 3.7 Implement dynamic source ban storage and early enforcement using OpenResty shared dictionaries.
- [x] 3.8 Extend rate-limit enforcement to create temporary bans after configured repeated violations.
- [x] 3.9 Add or update gateway smoke tests for normalization, score threshold blocking, body inspection, upload metadata inspection, and dynamic bans.

## 4. Logging And Observability API

- [x] 4.1 Extend gateway WAF event output with optional normalized target, cumulative score, threshold, body metadata, upload metadata, ban reason, ban duration, and remaining ban duration fields.
- [x] 4.2 Ensure gateway logs never include full request bodies, Authorization, Cookie, configured sensitive headers, or unbounded matched values.
- [x] 4.3 Extend API ingestion models and storage for advanced WAF event fields in both memory and PostgreSQL storage paths.
- [x] 4.4 Extend attack-log query filters for advanced target, event type, and minimum score.
- [x] 4.5 Extend observability summary responses with score-threshold block, body detection, upload detection, and dynamic-ban counters.
- [x] 4.6 Add API tests for advanced log ingestion, query filtering, summary aggregation, and sensitive payload omission.

## 5. Dashboard

- [x] 5.1 Update rule management forms and tables to support advanced rule targets using real API data and no mock rows.
- [x] 5.2 Update policy management forms to edit score thresholds, threshold action, normalization options, body/upload limits, and dynamic-ban settings.
- [x] 5.3 Update rate-limit management forms to edit repeated-violation and temporary-ban settings.
- [x] 5.4 Update publish confirmation views to show advanced protection changes from the preview API.
- [x] 5.5 Update attack log views to display advanced protection fields in table or detail views when returned by the API.
- [x] 5.6 Update dashboard metrics to display advanced protection counters from the summary API.
- [x] 5.7 Add frontend build/type checks and focused component or composable tests where existing test patterns support them.

## 6. Documentation And Verification

- [x] 6.1 Update deployment examples and environment documentation for gateway shared dictionary sizing and advanced inspection limits.
- [x] 6.2 Add a validation document or extend existing gateway verification docs with curl examples for encoded payloads, score accumulation, JSON body detection, upload metadata detection, CC repeated violations, and dynamic bans.
- [x] 6.3 Run `go test ./...` in `codes/litewaf-api` and record the result.
- [x] 6.4 Run `npm run build` in `codes/litewaf-dashboard` and record the result.
- [x] 6.5 Run available gateway smoke validation scripts, or document Docker/OpenResty environment blockers if local runtime remains unavailable.
