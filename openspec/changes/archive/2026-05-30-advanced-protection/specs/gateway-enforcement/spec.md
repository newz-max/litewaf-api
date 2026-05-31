## MODIFIED Requirements

### Requirement: Gateway inspects request parameters
The gateway SHALL inspect configured request targets for enabled rules before proxying to upstream, using bounded normalized inspection values for supported targets and preserving existing `pass`, `log-only`, and `block` action semantics.

#### Scenario: Query parameter matches block rule
- **WHEN** a request query parameter matches an enabled `block` rule for the site policy
- **THEN** the gateway returns HTTP 403 without sending the request to upstream

#### Scenario: Query parameter matches log-only rule
- **WHEN** a request query parameter matches an enabled `log-only` rule for the site policy
- **THEN** the gateway records the match and still proxies the request to upstream

#### Scenario: Query parameter matches pass rule
- **WHEN** a request query parameter matches an enabled `pass` rule for the site policy
- **THEN** the gateway allows the request to continue without blocking due to that rule

#### Scenario: Normalized parameter matches block rule
- **WHEN** a request query parameter only matches a block rule after configured normalization
- **THEN** the gateway returns HTTP 403 without sending the request to upstream

## ADDED Requirements

### Requirement: Gateway enforces policy score thresholds
The gateway SHALL accumulate rule scores during a request and enforce the published policy score threshold after evaluating configured inspection targets.

#### Scenario: Score threshold blocks request
- **WHEN** matched enabled rules produce a cumulative score that reaches a policy block threshold
- **THEN** the gateway blocks the request and records the score, threshold, and matched rule identifiers

#### Scenario: Immediate block still wins
- **WHEN** a matched rule has action `block`
- **THEN** the gateway blocks the request even if the cumulative score is below the policy threshold

### Requirement: Gateway enforces body and upload inspection decisions
The gateway SHALL include enabled body and upload inspection targets in the request enforcement flow after access-list and rate-limit checks and before proxying to upstream.

#### Scenario: Body inspection block
- **WHEN** an enabled body-targeted rule matches inspected body content
- **THEN** the gateway blocks the request according to the rule or score decision

#### Scenario: Upload inspection block
- **WHEN** an enabled upload-targeted rule matches inspected upload metadata
- **THEN** the gateway blocks the request according to the rule or score decision

### Requirement: Gateway checks dynamic bans before normal enforcement
The gateway SHALL check active dynamic source bans before access-list, rate-limit, and WAF rule evaluation.

#### Scenario: Active ban short-circuits enforcement
- **WHEN** a request arrives from an actively banned source IP
- **THEN** the gateway returns a block response without proxying or running later WAF checks

