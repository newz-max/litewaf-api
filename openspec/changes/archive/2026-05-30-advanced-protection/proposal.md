## Why

LiteWaf already has the MVP protection loop, management controls, and observability baseline, but gateway detection still relies mainly on direct parameter matching and simple blocking decisions. The next stage should improve coverage against encoded payloads, cumulative low-risk signals, body-based attacks, upload abuse, and repeat offenders while keeping the gateway hot path lightweight.

## What Changes

- Add request normalization before rule matching, including URL decoding, case normalization where appropriate, and path normalization.
- Add risk scoring so multiple matching rules can accumulate a score and trigger a policy threshold even when individual rules are not immediate block rules.
- Add request body inspection for selected content types and paths, with safe size limits and sensitive-data logging constraints.
- Add file upload inspection for filename, extension, MIME type, and size metadata.
- Extend rate-limit enforcement into stronger CC protection with temporary ban behavior for repeated threshold violations.
- Add dynamic source IP banning after high-risk WAF matches or repeated abusive behavior.
- Keep optional detection engines such as libinjection and Hyperscan outside this change; this change should not require native build dependencies.

## Capabilities

### New Capabilities
- `advanced-request-inspection`: Gateway-side normalization, risk scoring, request body inspection, and file upload inspection behavior.
- `dynamic-source-ban`: Temporary source IP banning caused by severe or repeated gateway enforcement events.

### Modified Capabilities
- `gateway-enforcement`: Gateway rule evaluation order and enforcement outcomes change to include normalized inputs, score thresholds, body/upload targets, and dynamic bans.
- `rate-limit-management`: Published rate-limit behavior changes to support CC-style repeated violation handling and temporary bans.
- `config-publishing`: Published gateway configuration changes to include advanced inspection settings, risk thresholds, body/upload limits, and dynamic ban settings.
- `rule-management`: Rule definitions change to support advanced targets and score-based enforcement.
- `policy-management`: Policy behavior changes to configure score thresholds and advanced inspection options per site policy.
- `gateway-observability`: Gateway events change to include normalized-match context, score-based decisions, body/upload inspection metadata, and dynamic-ban events without logging sensitive body content.
- `log-management`: Stored WAF event data and queries change to preserve advanced enforcement fields needed for audit and analysis.
- `dashboard-observability`: Dashboard views change to surface score-based blocks, body/upload detections, and dynamic-ban activity from real API data.

## Impact

- Affected gateway code: OpenResty Lua request normalization, rule matching, body reading safeguards, multipart metadata extraction, rate-limit/ban dictionaries, and WAF event output.
- Affected API code: rule/policy validation, publish payload generation, log ingestion/storage/query models, and observability summary fields.
- Affected dashboard code: rule and policy forms, observability/log views, and any management UI needed for score thresholds and advanced inspection controls.
- Affected docs/deploy: environment variables and validation instructions for advanced inspection limits and gateway shared dictionaries.
- No breaking API removals are intended; existing rules, policies, access lists, and rate-limit rules should continue to publish and enforce with default advanced options disabled or conservative.
