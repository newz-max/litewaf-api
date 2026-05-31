## MODIFIED Requirements

### Requirement: Gateway emits structured WAF logs
The gateway SHALL emit JSON log entries for WAF rule, access-list, and rate-limit matches containing site, enforcement source, action, request ID, request metadata, and final disposition available in the request context.

#### Scenario: Blocked request logs rule match
- **WHEN** the gateway blocks a request because of a matching rule
- **THEN** stdout contains a JSON log entry identifying the matched rule, action, request ID, and final disposition

#### Scenario: Log-only request logs rule match
- **WHEN** the gateway observes a request because of a matching `log-only` rule
- **THEN** stdout contains a JSON log entry identifying the matched rule, action, request ID, and final disposition without blocking the request

#### Scenario: Access-list block logs match
- **WHEN** the gateway blocks a request because of a blacklist entry
- **THEN** stdout contains a JSON log entry identifying the matched access-list entry, action, request ID, and final disposition

#### Scenario: Rate-limit rejection logs match
- **WHEN** the gateway rejects a request because of a rate-limit rule
- **THEN** stdout contains a JSON log entry identifying the matched rate-limit rule, action, request ID, and final disposition
