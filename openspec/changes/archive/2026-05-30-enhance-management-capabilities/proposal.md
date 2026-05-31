## Why

LiteWaf has completed the MVP protection loop, but the control plane is still open and lacks the operational controls needed for real administration. The next stage should make management actions authenticated, authorized, auditable, and safer to publish or roll back.

## What Changes

- Add administrator login and token-based access for management APIs.
- Protect `/api/v1` management endpoints with authentication middleware while preserving public health/version behavior.
- Add role-based access control for administrator, auditor, and read-only users.
- Record audit logs for create, update, delete, publish, and rollback operations.
- Add black/white list management for IP, CIDR, URI, and User-Agent matching.
- Add rate limit configuration for IP, URI, and site-level controls.
- Validate rule expressions and policy completeness before publishing gateway configuration.
- Support rolling back to a historical published version and regenerate the active gateway configuration from that version.
- Add dashboard login, role-aware menus/actions, black/white list pages, rate limit pages, publish confirmation, and rollback flows.

## Capabilities

### New Capabilities

- `admin-authentication`: Administrator login, token issuance, session identity, and authenticated API access.
- `role-based-access-control`: Role definitions and permission enforcement for administrator, auditor, and read-only users.
- `audit-logging`: Durable audit records for management and release operations.
- `access-list-management`: Control-plane CRUD and gateway publishing support for IP, CIDR, URI, and User-Agent black/white lists.
- `rate-limit-management`: Control-plane CRUD and gateway publishing support for IP, URI, and site-level rate limits.

### Modified Capabilities

- `config-publishing`: Publish validation, publish confirmation support, and rollback to historical versions.
- `gateway-enforcement`: Gateway enforcement of published black/white list and rate limit configuration.

## Impact

- Backend API adds authentication, authorization, audit, access-list, rate-limit, validation, and rollback endpoints under `/api/v1`.
- Backend persistence adds user/role, audit log, access-list, rate-limit, and rollback-related storage.
- Gateway configuration format expands to include access lists and rate limit policies.
- OpenResty gateway enforcement expands to short-circuit black/white list decisions and apply published rate limits.
- Dashboard adds login state, role-aware navigation/actions, new management pages, and safer publish/rollback workflows.
- Tests must cover protected endpoints, permission boundaries, audit recording, publish validation, rollback behavior, and gateway enforcement.
