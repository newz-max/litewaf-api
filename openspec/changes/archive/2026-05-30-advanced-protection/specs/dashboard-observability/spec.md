## MODIFIED Requirements

### Requirement: Dashboard displays attack logs
The dashboard SHALL provide an attack log page backed by the attack log API and display advanced protection fields when returned by the API.

#### Scenario: Attack log page loads records
- **WHEN** an allowed user opens the attack log page
- **THEN** the dashboard requests attack logs from the API and displays the returned records

#### Scenario: Attack log filters submit API query
- **WHEN** an allowed user filters attack logs by time range, site, client IP, rule, action, or disposition
- **THEN** the dashboard calls the attack log API with matching query parameters and displays the filtered result

#### Scenario: Attack log page shows empty state
- **WHEN** the attack log API returns an empty list
- **THEN** the dashboard displays an empty state instead of mock records

#### Scenario: Attack log displays advanced fields
- **WHEN** the attack log API returns score, advanced target, body metadata, upload metadata, or dynamic-ban fields
- **THEN** the dashboard displays those fields in the attack log table or detail view

### Requirement: Dashboard displays observability metrics
The dashboard SHALL display traffic and protection metrics using real summary API data, including advanced protection metrics when present.

#### Scenario: Metrics page loads summary
- **WHEN** an allowed user opens the dashboard metrics view
- **THEN** the dashboard requests summary metrics from the API and displays request count, block count, WAF match count, and rate-limit count

#### Scenario: Metrics page displays top lists
- **WHEN** the summary API returns top IP, URI, rule, and attack type lists
- **THEN** the dashboard displays those ranked lists from API data

#### Scenario: Metrics page handles no data
- **WHEN** the summary API returns zero counts and empty top lists
- **THEN** the dashboard displays empty or zero states instead of mock metrics

#### Scenario: Metrics page displays advanced counters
- **WHEN** the summary API returns score-threshold, body detection, upload detection, or dynamic-ban counters
- **THEN** the dashboard displays those values from API data

