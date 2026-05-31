# gateway-observability Specification

## Purpose
TBD - created by archiving change add-observability-logs. Update Purpose after archive.
## Requirements
### Requirement: Gateway emits JSON access logs
The OpenResty gateway SHALL emit one structured JSON access log entry for each completed request handled by the gateway.

#### Scenario: Proxied request access log
- **WHEN** the gateway proxies a request to a configured upstream
- **THEN** stdout contains a JSON access log entry with timestamp, request ID, host, method, URI, status, upstream status when available, duration, client IP, and disposition `proxied`

#### Scenario: Rejected request access log
- **WHEN** the gateway rejects a request before proxying because the host is unknown or the request is invalid
- **THEN** stdout contains a JSON access log entry with request metadata, response status, and disposition `rejected`

#### Scenario: Blocked request access log
- **WHEN** the gateway blocks a request because of WAF, access-list, or rate-limit enforcement
- **THEN** stdout contains a JSON access log entry with request metadata, response status, and disposition `blocked`

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

### Requirement: Gateway log entries are correlatable
The gateway SHALL attach a stable request ID to access logs, WAF event logs, and upstream request headers for the same request.

#### Scenario: Request ID generated when missing
- **WHEN** a client request does not provide a request ID header
- **THEN** the gateway generates a request ID and uses it in all log entries for that request

#### Scenario: Request ID propagated when present
- **WHEN** a client request provides an accepted request ID header
- **THEN** the gateway propagates that request ID to upstream and uses it in all log entries for that request

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

