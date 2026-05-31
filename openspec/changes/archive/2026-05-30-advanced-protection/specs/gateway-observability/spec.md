## MODIFIED Requirements

### Requirement: Gateway emits JSON WAF event logs
The gateway SHALL emit structured JSON WAF event logs for every rule, access-list, rate-limit, score-threshold, body-inspection, upload-inspection, and dynamic-ban match that affects request disposition or is configured for observation.

#### Scenario: Rule match event log
- **WHEN** a request matches an enabled WAF rule
- **THEN** stdout contains a JSON WAF event log with timestamp, request ID, site ID, rule ID, rule type, target, action, matched value summary, and final disposition

#### Scenario: Access-list match event log
- **WHEN** a request matches a published whitelist or blacklist entry
- **THEN** stdout contains a JSON WAF event log with timestamp, request ID, site ID, list entry ID, list type, match target, action, and final disposition

#### Scenario: Rate-limit match event log
- **WHEN** a request exceeds a published rate-limit rule
- **THEN** stdout contains a JSON WAF event log with timestamp, request ID, site ID, rate-limit rule ID, threshold, window, action, and final disposition

#### Scenario: Score threshold event log
- **WHEN** a request reaches a published policy score threshold
- **THEN** stdout contains a JSON WAF event log with timestamp, request ID, site ID, matched rule identifiers, cumulative score, threshold, action, and final disposition

#### Scenario: Body inspection event log
- **WHEN** body inspection contributes to a WAF event
- **THEN** stdout contains bounded body inspection metadata without the full request body

#### Scenario: Upload inspection event log
- **WHEN** upload inspection contributes to a WAF event
- **THEN** stdout contains upload filename, extension, MIME type, and size metadata when available and allowed by sensitive-data controls

### Requirement: Gateway logs avoid sensitive payload storage
The gateway SHALL avoid logging full request bodies, authorization headers, cookies, configured sensitive headers, or unbounded matched values in access and WAF event logs.

#### Scenario: Sensitive header redaction
- **WHEN** a request includes an authorization or cookie header
- **THEN** gateway log entries omit or redact those header values

#### Scenario: Matched value is summarized
- **WHEN** a WAF rule match includes a long or sensitive request value
- **THEN** the WAF event log stores a bounded summary rather than the full unbounded value

#### Scenario: Body match is summarized
- **WHEN** a body-targeted rule matches inspected body content
- **THEN** the WAF event log stores target metadata and a bounded match summary rather than the full body

