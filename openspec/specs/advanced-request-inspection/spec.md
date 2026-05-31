# advanced-request-inspection Specification

## Purpose
TBD - created by archiving change advanced-protection. Update Purpose after archive.
## Requirements
### Requirement: Gateway normalizes inspection inputs
The gateway SHALL create bounded normalized inspection values before evaluating WAF rules, including decoded URI components, normalized paths, query values, and configured headers, while preserving the original request sent upstream.

#### Scenario: Encoded query payload is normalized
- **WHEN** a request query value contains URL-encoded attack text
- **THEN** the gateway evaluates the decoded bounded value against enabled rules

#### Scenario: Path traversal syntax is normalized
- **WHEN** a request path contains redundant slashes, dot segments, or encoded path separators
- **THEN** the gateway evaluates a normalized path value for path-targeted rules

#### Scenario: Original request is preserved for upstream
- **WHEN** a normalized request does not trigger a blocking decision
- **THEN** the gateway proxies the original request form to the upstream service

### Requirement: Gateway supports score-based enforcement
The gateway SHALL accumulate scores from matched enabled rules within a request and apply the published policy threshold action when the accumulated score reaches or exceeds the threshold.

#### Scenario: Multiple low-score matches exceed threshold
- **WHEN** a request matches multiple enabled rules whose combined score reaches the policy threshold
- **THEN** the gateway applies the configured threshold action and records a score-based WAF event

#### Scenario: Score below threshold is observed
- **WHEN** a request matches enabled scored rules but the combined score remains below the policy threshold
- **THEN** the gateway continues normal processing unless an individual matched rule requires blocking

### Requirement: Gateway inspects configured request bodies
The gateway SHALL inspect request body content only when the published policy enables body inspection for the request path and content type and the body remains within the configured inspection limit.

#### Scenario: JSON body field matches rule
- **WHEN** a request with an enabled JSON content type contains a body value matching a body-targeted block rule
- **THEN** the gateway blocks the request and records a WAF event without storing the full body

#### Scenario: Unsupported body content type is skipped
- **WHEN** a request content type is not enabled for body inspection
- **THEN** the gateway skips body inspection and continues evaluating other configured targets

#### Scenario: Oversized body is handled by policy
- **WHEN** a request body exceeds the published maximum inspected bytes
- **THEN** the gateway applies the configured oversized-body action and records the decision

### Requirement: Gateway inspects upload metadata
The gateway SHALL inspect configured multipart upload metadata, including filename, extension, MIME type, and size, without requiring full file-content scanning.

#### Scenario: Dangerous upload extension is blocked
- **WHEN** a multipart upload filename or extension matches an enabled upload-targeted block rule
- **THEN** the gateway blocks the request and records upload metadata in the WAF event

#### Scenario: Upload exceeds size limit
- **WHEN** an uploaded part exceeds the published upload size limit for the policy
- **THEN** the gateway applies the configured upload-size action before proxying

#### Scenario: Safe upload metadata is allowed
- **WHEN** upload metadata does not match any blocking rule and remains within limits
- **THEN** the gateway continues normal WAF evaluation and proxy behavior

