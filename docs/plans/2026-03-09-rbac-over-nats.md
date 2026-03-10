# RBAC Over NATS Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add NATS-based coarse-grained auth callout and fine-grained request/reply RBAC checks without rewriting the existing RBAC policy and repository core.

**Architecture:** Introduce a shared identity layer that converts verified IdP JWT claims into a trusted caller context, then reuse the current RBAC service and policy engine behind both HTTP and NATS adapters. Keep auth callout limited to connection admission and fixed subject grants while moving resource-level authorization to `rbac.check` request/reply handlers.

**Tech Stack:** Go 1.24, Echo, NATS, JWT/JWKS verification, MongoDB, testify

---

### Task 1: Introduce Shared Caller Identity

**Files:**
- Create: `internal/rbac/identity/caller_context.go`
- Create: `internal/rbac/identity/context.go`
- Modify: `internal/rbac/service/service_common.go`
- Modify: `internal/rbac/service/service_system.go`
- Modify: `internal/rbac/service/service_resource.go`
- Test: `tests/identity_caller_context_test.go`

**Step 1: Write the failing test**

Add tests that assert a trusted caller context can carry `user_id`, `user_type`, tenant, and org ids into the RBAC service entry points without relying on HTTP headers.

**Step 2: Run test to verify it fails**

Run: `go test ./tests -run TestCallerContext -v`

Expected: FAIL because the caller context types and service signatures do not exist yet.

**Step 3: Write minimal implementation**

- Add a `CallerContext` type and helper functions for storing and retrieving it from `context.Context`.
- Refactor service methods that currently accept `callerID string` to instead accept a trusted caller identity object or extract one from context.
- Keep behavior unchanged apart from the new identity boundary.

**Step 4: Run test to verify it passes**

Run: `go test ./tests -run TestCallerContext -v`

Expected: PASS

**Step 5: Commit**

```bash
git add internal/rbac/identity/caller_context.go internal/rbac/identity/context.go internal/rbac/service/service_common.go internal/rbac/service/service_system.go internal/rbac/service/service_resource.go tests/identity_caller_context_test.go
git commit -m "refactor: introduce shared caller context"
```

### Task 2: Add Shared JWT Verification

**Files:**
- Create: `internal/rbac/identity/jwt_verifier.go`
- Create: `internal/rbac/identity/claims_mapper.go`
- Modify: `internal/rbac/config/config.go`
- Test: `tests/jwt_verifier_test.go`

**Step 1: Write the failing test**

Add tests for:

- valid JWT produces a `CallerContext`
- wrong issuer is rejected
- wrong audience is rejected
- expired token is rejected

**Step 2: Run test to verify it fails**

Run: `go test ./tests -run TestJWTVerifier -v`

Expected: FAIL because no verifier or config exists.

**Step 3: Write minimal implementation**

- Add verifier config for issuer, audience, and JWKS URL or equivalent key source.
- Implement JWT verification and claims mapping into `CallerContext`.
- Keep the mapper strict about namespace and tenant claim sources.

**Step 4: Run test to verify it passes**

Run: `go test ./tests -run TestJWTVerifier -v`

Expected: PASS

**Step 5: Commit**

```bash
git add internal/rbac/identity/jwt_verifier.go internal/rbac/identity/claims_mapper.go internal/rbac/config/config.go tests/jwt_verifier_test.go
git commit -m "feat: add shared jwt verifier"
```

### Task 3: Refactor HTTP Adapters To Use Shared Identity

**Files:**
- Create: `internal/rbac/identity/jwks_source.go`
- Modify: `internal/rbac/handler/handler_common.go`
- Modify: `internal/rbac/handler/handler_system.go`
- Modify: `internal/rbac/handler/handler_resource.go`
- Modify: `internal/rbac/handler/rbac_middleware.go`
- Modify: `internal/rbac/router/router.go`
- Modify: `cmd/server/main.go`
- Modify: `tests/helper_test.go`
- Test: `tests/http_identity_adapter_test.go`

**Step 1: Write the failing test**

Add tests proving HTTP handlers and middleware can:

- read a bearer token
- build a `CallerContext`
- invoke the RBAC core without reading `x-user-id`
- accept verifier injection in test setup so handlers and middleware share the same identity path

**Step 2: Run test to verify it fails**

Run: `go test ./tests -run TestHTTPIdentityAdapter -v`

Expected: FAIL because handlers still require `x-user-id`.

**Step 3: Write minimal implementation**

- Replace direct `x-user-id` extraction with shared JWT verification.
- Add a production key source that can resolve signing keys from JWKS or an equivalent configured source.
- Thread the verifier through handler and middleware constructors so runtime code and tests use the same entry point.
- Update HTTP CORS and request parsing to accept `Authorization: Bearer <token>`.
- Keep request validation and error mapping behavior equivalent to current handlers.
- Preserve backward compatibility only if needed for migration; otherwise remove the header dependency.

**Step 4: Run test to verify it passes**

Run: `go test ./tests -run TestHTTPIdentityAdapter -v`

Expected: PASS

**Step 5: Commit**

```bash
git add internal/rbac/identity/jwks_source.go internal/rbac/handler/handler_common.go internal/rbac/handler/handler_system.go internal/rbac/handler/handler_resource.go internal/rbac/handler/rbac_middleware.go internal/rbac/router/router.go cmd/server/main.go tests/helper_test.go tests/http_identity_adapter_test.go
git commit -m "refactor: route http identity through jwt verifier"
```

### Task 4: Add NATS Request/Reply Contracts

**Files:**
- Create: `internal/rbac/transport/nats/contracts.go`
- Create: `internal/rbac/transport/nats/subjects.go`
- Create: `internal/rbac/transport/nats/errors.go`
- Test: `tests/nats_contracts_test.go`

**Step 1: Write the failing test**

Add tests that validate:

- stable subject names
- request envelope decoding
- response envelope encoding
- error code mapping for unauthorized, forbidden, bad request, and internal error

**Step 2: Run test to verify it fails**

Run: `go test ./tests -run TestNATSContracts -v`

Expected: FAIL because the NATS transport contract types do not exist.

**Step 3: Write minimal implementation**

- Define subject constants for `rbac.check`, `rbac.check.batch`, `rbac.roles.me`, and the internal auth callout path.
- Define shared request and response envelopes.
- Add transport-level error mapping helpers.

**Step 4: Run test to verify it passes**

Run: `go test ./tests -run TestNATSContracts -v`

Expected: PASS

**Step 5: Commit**

```bash
git add internal/rbac/transport/nats/contracts.go internal/rbac/transport/nats/subjects.go internal/rbac/transport/nats/errors.go tests/nats_contracts_test.go
git commit -m "feat: define nats rbac contracts"
```

### Task 5: Implement `rbac.check`, `rbac.check.batch`, And `rbac.roles.me`

**Files:**
- Create: `internal/rbac/transport/nats/server.go`
- Create: `internal/rbac/transport/nats/handlers.go`
- Modify: `internal/rbac/config/config.go`
- Modify: `cmd/server/main.go`
- Modify: `go.mod`
- Modify: `go.sum`
- Test: `tests/nats_permission_handlers_test.go`

**Step 1: Write the failing test**

Add tests covering:

- `rbac.check` allows a known permission
- `rbac.check` rejects invalid request bodies
- `rbac.check.batch` returns a result map
- `rbac.roles.me` returns only the caller's roles
- server construction can accept NATS runtime config and a verifier without relying on HTTP setup

**Step 2: Run test to verify it fails**

Run: `go test ./tests -run TestNATSPermissionHandlers -v`

Expected: FAIL because there is no NATS transport implementation.

**Step 3: Write minimal implementation**

- Add NATS runtime config for server URL and any handler setup needed by `cmd/server/main.go`.
- Add the NATS Go client dependency to the module.
- Create a NATS transport server that subscribes to the three public RBAC subjects.
- Verify the JWT from the request envelope, construct `CallerContext`, and dispatch into the RBAC core.
- Return consistent response envelopes and request ids.

**Step 4: Run test to verify it passes**

Run: `go test ./tests -run TestNATSPermissionHandlers -v`

Expected: PASS

**Step 5: Commit**

```bash
git add internal/rbac/transport/nats/server.go internal/rbac/transport/nats/handlers.go internal/rbac/config/config.go cmd/server/main.go go.mod go.sum tests/nats_permission_handlers_test.go
git commit -m "feat: add nats rbac request handlers"
```

### Task 6: Implement NATS Auth Callout

**Files:**
- Create: `internal/rbac/transport/nats/auth_callout.go`
- Create: `internal/rbac/transport/nats/grants.go`
- Modify: `internal/rbac/config/config.go`
- Modify: `internal/rbac/transport/nats/server.go`
- Test: `tests/nats_auth_callout_test.go`

**Step 1: Write the failing test**

Add tests covering:

- valid JWT receives allow with expected subjects
- expired JWT is denied
- malformed claims are denied
- auth callout never returns resource-specific subject grants
- coarse-grained grants can include only configured application request prefixes

**Step 2: Run test to verify it fails**

Run: `go test ./tests -run TestNATSAuthCallout -v`

Expected: FAIL because there is no auth callout implementation.

**Step 3: Write minimal implementation**

- Add auth callout request and response handling.
- Extend config with the approved application request prefix or prefixes used for coarse grants.
- Reuse the shared verifier and caller mapper.
- Return only coarse-grained subject grants for `_INBOX.>`, `rbac.check`, `rbac.check.batch`, `rbac.roles.me`, and any approved application request prefix.

**Step 4: Run test to verify it passes**

Run: `go test ./tests -run TestNATSAuthCallout -v`

Expected: PASS

**Step 5: Commit**

```bash
git add internal/rbac/transport/nats/auth_callout.go internal/rbac/transport/nats/grants.go internal/rbac/config/config.go internal/rbac/transport/nats/server.go tests/nats_auth_callout_test.go
git commit -m "feat: add nats auth callout"
```

### Task 7: Add Limits, Metrics, And Operational Safeguards

**Files:**
- Modify: `internal/rbac/transport/nats/handlers.go`
- Modify: `internal/rbac/transport/nats/auth_callout.go`
- Modify: `internal/rbac/util/logger.go`
- Test: `tests/nats_operational_guards_test.go`

**Step 1: Write the failing test**

Add tests covering:

- `rbac.check.batch` rejects oversized payloads
- request ids are echoed in error responses
- deny decisions include stable reason codes

**Step 2: Run test to verify it fails**

Run: `go test ./tests -run TestNATSOperationalGuards -v`

Expected: FAIL because the transport has no safeguards yet.

**Step 3: Write minimal implementation**

- Enforce maximum batch size and bounded request payload size.
- Emit structured logs for auth callout and request/reply decisions.
- Add consistent reason codes and latency metadata in responses.

**Step 4: Run test to verify it passes**

Run: `go test ./tests -run TestNATSOperationalGuards -v`

Expected: PASS

**Step 5: Commit**

```bash
git add internal/rbac/transport/nats/handlers.go internal/rbac/transport/nats/auth_callout.go internal/rbac/util/logger.go tests/nats_operational_guards_test.go
git commit -m "chore: harden nats rbac transport"
```

### Task 8: Run Full Verification And Update Docs

**Files:**
- Modify: `docs/rbac_system_spec.md`
- Modify: `docs/rbac.yaml`
- Modify: `README.md`
- Test: `tests/`

**Step 1: Write the failing test**

Add or update any integration coverage needed to prove NATS and HTTP paths share identity behavior and RBAC decisions.

**Step 2: Run targeted tests**

Run: `go test ./tests -run "TestCallerContext|TestJWTVerifier|TestHTTPIdentityAdapter|TestNATSContracts|TestNATSPermissionHandlers|TestNATSAuthCallout|TestNATSOperationalGuards" -v`

Expected: PASS

**Step 3: Run full verification**

Run: `go test ./...`

Expected: PASS

**Step 4: Update docs**

- Document the new caller identity flow
- Document NATS subjects and schemas
- Document auth callout behavior and failure policy

**Step 5: Commit**

```bash
git add docs/rbac_system_spec.md docs/rbac.yaml README.md tests
git commit -m "docs: describe rbac over nats"
```


