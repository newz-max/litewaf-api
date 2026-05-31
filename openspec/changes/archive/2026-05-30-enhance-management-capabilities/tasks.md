## 1. Backend Foundation

- [x] 1.1 Add additive database initialization for users, audit logs, access list entries, rate limit rules, and publish rollback metadata.
- [x] 1.2 Extend in-memory storage with the same user, audit, access list, rate limit, and publish rollback behavior as PostgreSQL.
- [x] 1.3 Add environment configuration for token signing secret, token expiry, and initial administrator bootstrap without hard-coded production credentials.
- [x] 1.4 Add repository interfaces and tests for users, audit logs, access lists, rate limits, and publish version payload retrieval.

## 2. Authentication and Authorization

- [x] 2.1 Implement password hashing and credential verification for administrator login.
- [x] 2.2 Add login API returning token, expiry, user identity, and role on valid credentials.
- [x] 2.3 Add bearer-token middleware for protected `/api/v1` management routes while leaving `/healthz` and `/api/v1/version` public.
- [x] 2.4 Add fixed role permission checks for administrator, auditor, and read-only users.
- [x] 2.5 Add backend tests for valid login, invalid login, missing token, expired token, allowed role actions, and forbidden role actions.

## 3. Audit Logging

- [x] 3.1 Implement shared audit logging service for successful and failed mutating operations.
- [x] 3.2 Record audit entries for site, rule, policy, access list, rate limit, publish, and rollback operations.
- [x] 3.3 Add protected audit log list endpoint with filters for time range, actor, action, resource type, and result.
- [x] 3.4 Add tests verifying audit records are created and audit queries return filtered or empty lists correctly.

## 4. Access List Management

- [x] 4.1 Add access list API endpoints for create, list, update, and delete with role checks.
- [x] 4.2 Validate access list target type, action, enabled state, IP, CIDR, URI, and User-Agent values before persistence.
- [x] 4.3 Include enabled access list entries in published gateway configuration.
- [x] 4.4 Add backend tests for access list CRUD, invalid CIDR rejection, disabled entries, and publish output.

## 5. Rate Limit Management

- [x] 5.1 Add rate limit API endpoints for create, list, update, and delete with role checks.
- [x] 5.2 Validate rate limit scope, match criteria, threshold, window, action, and ban duration before persistence.
- [x] 5.3 Include enabled rate limit rules in published gateway configuration.
- [x] 5.4 Add backend tests for rate limit CRUD, invalid numeric values, empty lists, disabled rules, and publish output.

## 6. Publish Validation and Rollback

- [x] 6.1 Add publish validation for rule expressions, site upstreams, policy bindings, access list entries, and rate limit rules.
- [x] 6.2 Add publish preview or summary API covering changed sites, policies, rules, access lists, and rate limits.
- [x] 6.3 Add rollback API that restores a previous successful publish payload and records rollback status.
- [x] 6.4 Reject rollback to failed or nonexistent publish versions without changing active gateway configuration.
- [x] 6.5 Add tests for validation failures, successful publish, publish summary, successful rollback, rejected rollback, and audit records.

## 7. Gateway Enforcement

- [x] 7.1 Extend gateway config loading to parse published access list and rate limit sections.
- [x] 7.2 Enforce access lists in order: whitelist, blacklist, then existing rate limit and WAF rule logic.
- [x] 7.3 Enforce IP, URI, and site-level rate limits before existing WAF rule inspection.
- [x] 7.4 Emit structured JSON logs for access list blocks and rate limit rejections.
- [x] 7.5 Add gateway verification cases for whitelist allow, blacklist block, rate limit allow, rate limit reject, and logging.

## 8. Dashboard Authentication and Roles

- [x] 8.1 Add dashboard login page and auth state management for token, expiry, user identity, and role.
- [x] 8.2 Attach bearer token to protected API requests and clear session state on HTTP 401.
- [x] 8.3 Add route guards so unauthenticated users are sent to login before accessing console pages.
- [x] 8.4 Make navigation, buttons, and destructive actions role-aware for administrator, auditor, and read-only users.
- [x] 8.5 Add frontend tests or build-time checks covering auth state and role-aware rendering where practical.

## 9. Dashboard Management Pages

- [x] 9.1 Add audit log page with real API data, filters, loading, empty, and error states.
- [x] 9.2 Add black/white list page with real CRUD APIs and role-aware write controls.
- [x] 9.3 Add rate limit configuration page with real CRUD APIs and role-aware write controls.
- [x] 9.4 Add publish confirmation flow that shows API summary and only activates publish after confirmation.
- [x] 9.5 Add rollback controls for successful publish records and show status from API responses.

## 10. Documentation and Verification

- [x] 10.1 Update API and deployment documentation for authentication settings, initial administrator bootstrap, roles, and protected endpoints.
- [x] 10.2 Update MVP or stage documentation with access list, rate limit, publish validation, and rollback verification steps.
- [x] 10.3 Run `go test ./...` in `codes/litewaf-api`.
- [x] 10.4 Run `npm run build` in `codes/litewaf-dashboard`.
- [x] 10.5 Run gateway or Compose smoke tests when Docker is available, and document any environment blocker if Docker is unavailable.
