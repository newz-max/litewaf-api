## MODIFIED Requirements

### Requirement: Baseline SQLi and XSS rules are available
The system SHALL provide baseline SQLi, XSS, and RCE-like rules that can be seeded as real managed rules, enabled, bound to policies, and published for MVP and open-source validation.

#### Scenario: Baseline SQLi rule exists
- **WHEN** a fresh MVP or quick-start environment is initialized or seeded
- **THEN** at least one SQLi detection rule is available for query parameter inspection through the rule API and dashboard

#### Scenario: Baseline XSS rule exists
- **WHEN** a fresh MVP or quick-start environment is initialized or seeded
- **THEN** at least one XSS detection rule is available for query parameter inspection through the rule API and dashboard

#### Scenario: Baseline RCE-like rule exists
- **WHEN** a fresh quick-start environment is initialized or seeded
- **THEN** at least one RCE-like detection rule is available through the rule API and dashboard using a target supported by the gateway inspection model

#### Scenario: Default rule seed is idempotent
- **WHEN** default baseline rule seeding is executed repeatedly
- **THEN** the API storage contains one deterministic managed rule per default rule identifier instead of duplicates
