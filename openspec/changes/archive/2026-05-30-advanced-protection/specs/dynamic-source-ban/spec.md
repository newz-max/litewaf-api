## ADDED Requirements

### Requirement: Gateway enforces dynamic source bans
The gateway SHALL temporarily ban source IPs when published dynamic-ban settings are enabled and a request meets a configured ban trigger.

#### Scenario: High-risk WAF match creates ban
- **WHEN** a request triggers a published dynamic-ban rule because of a high-risk WAF match
- **THEN** the gateway records a temporary ban for the source IP with the configured duration

#### Scenario: Banned source is blocked early
- **WHEN** a request arrives from a source IP with an active temporary ban
- **THEN** the gateway blocks the request before normal access-list, rate-limit, or WAF rule evaluation

#### Scenario: Ban expires
- **WHEN** the configured ban duration has elapsed for a source IP
- **THEN** the gateway no longer blocks requests solely because of that expired ban

### Requirement: Dynamic bans are observable
The gateway SHALL emit structured WAF events when it creates, refreshes, expires by lookup, or enforces a temporary source ban.

#### Scenario: Ban creation event is logged
- **WHEN** the gateway creates a temporary source ban
- **THEN** stdout contains a WAF event with source IP, site, trigger type, ban duration, and final disposition

#### Scenario: Ban enforcement event is logged
- **WHEN** the gateway blocks a request because of an active temporary ban
- **THEN** stdout contains a WAF event identifying the ban reason and remaining ban duration

