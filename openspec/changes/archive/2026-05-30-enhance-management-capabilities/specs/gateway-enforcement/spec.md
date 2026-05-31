## ADDED Requirements

### Requirement: Gateway enforces published access lists
The OpenResty gateway SHALL enforce published IP, CIDR, URI, and User-Agent black and white list entries before existing WAF rule inspection.

#### Scenario: Whitelisted request is allowed
- **WHEN** a request matches an enabled whitelist entry for its site
- **THEN** the gateway allows the request to continue without blocking due to blacklist or WAF rule matches

#### Scenario: Blacklisted request is blocked
- **WHEN** a request matches an enabled blacklist entry for its site and does not match a whitelist entry
- **THEN** the gateway returns HTTP 403 without proxying the request to upstream

#### Scenario: Access list block is logged
- **WHEN** the gateway blocks a request because of an access list entry
- **THEN** stdout contains a JSON log entry identifying the matched access list entry and action

### Requirement: Gateway enforces published rate limits
The OpenResty gateway SHALL enforce published IP, URI, and site-level rate limit rules before existing WAF rule inspection.

#### Scenario: Request within rate limit is proxied
- **WHEN** a request matches an enabled rate limit rule but remains within the configured threshold and window
- **THEN** the gateway continues normal WAF evaluation and proxy behavior

#### Scenario: Request exceeding rate limit is rejected
- **WHEN** a request exceeds an enabled rate limit rule threshold within the configured window
- **THEN** the gateway returns a rate-limit response without proxying the request to upstream

#### Scenario: Rate limit event is logged
- **WHEN** the gateway rejects a request because of a rate limit rule
- **THEN** stdout contains a JSON log entry identifying the matched rate limit rule and action
