# Space ABAC Auth Platform Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade this auth platform repo to support space-scoped ABAC decisions backed by org snapshots, space principal bindings, compiled policy rule sets, and efficient batch decision evaluation.

**Architecture:** Keep OPA/Rego static and generic. Accept projection data from upstream systems, store it locally in MongoDB, resolve an effective subject from org snapshots plus space principal bindings, then load active compiled rule sets by `(space_id, resource_type, action)` and evaluate them in OPA. This repo will not own Space BE canonical policy editing or resource querying; it only owns projection ingestion and decision execution.

**Tech Stack:** Go, Echo, MongoDB, OPA/Rego, Testify, existing `tests/abac` harness.

---

## Scope

This plan only covers changes inside this repository.

Out of scope for this repo:

- Space BE canonical matrix editing UI
- Space BE compiler implementation
- FE capability aggregation endpoints
- Resource BE candidate resource querying

Required upstream integration contracts:

- Space BE publishes `space_principal_bindings`
- Space BE publishes compiled `space_policy_rule_sets` and activates a `policy_version`
- Org sync job publishes `org_user_snapshots`
- Space BE / Resource BE call internal decision APIs

## Task 1: Add Projection Models and Request Validation

**Files:**
- Create: `internal/abac/model/projection_types.go`
- Create: `internal/abac/model/projection_req.go`
- Modify: `internal/abac/model/check_access_req.go`
- Modify: `internal/abac/model/constants.go`
- Test: `tests/abac/projection_validation_test.go`

**Step 1: Write the failing test**

```go
func TestProjectionValidation(t *testing.T) {
	t.Run("binding projection requires space_id principal_type principal_id", func(t *testing.T) {
		req := model.UpsertSpacePrincipalBindingReq{}
		assert.Error(t, req.Validate())
	})

	t.Run("policy rule set upload requires space_id policy_version resource_type action", func(t *testing.T) {
		req := model.UpsertPolicyRuleSetReq{}
		assert.Error(t, req.Validate())
	})

	t.Run("decision request requires space_id", func(t *testing.T) {
		req := model.DecisionCheckReq{
			Action: "read",
			Resource: model.ResourceAttrs{
				ResourceID:   "doc_1",
				ResourceType: "document",
			},
		}
		assert.Error(t, req.Validate())
	})
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./tests/abac -run TestProjectionValidation -v`  
Expected: FAIL because the new projection request types do not exist yet.

**Step 3: Write minimal implementation**

Add new model types:

```go
type OrgUserSnapshot struct {
	UserID          string   `json:"user_id" bson:"user_id"`
	FunctionIDs     []string `json:"function_ids" bson:"function_ids"`
	DivisionID      string   `json:"division_id" bson:"division_id"`
	DeptID          string   `json:"dept_id" bson:"dept_id"`
	SectID          string   `json:"sect_id" bson:"sect_id"`
	EmploymentStatus string  `json:"employment_status" bson:"employment_status"`
	SourceUpdatedAt time.Time `json:"source_updated_at" bson:"source_updated_at"`
	SyncedAt        time.Time `json:"synced_at" bson:"synced_at"`
}

type SpacePrincipalBinding struct {
	SpaceID        string   `json:"space_id" bson:"space_id"`
	PrincipalType  string   `json:"principal_type" bson:"principal_type"`
	PrincipalID    string   `json:"principal_id" bson:"principal_id"`
	GrantTokens    []string `json:"grant_tokens" bson:"grant_tokens"`
	BindingVersion int64    `json:"binding_version" bson:"binding_version"`
}

type PolicyRuleSet struct {
	SpaceID        string         `json:"space_id" bson:"space_id"`
	PolicyVersion  int64          `json:"policy_version" bson:"policy_version"`
	ResourceType   string         `json:"resource_type" bson:"resource_type"`
	Action         string         `json:"action" bson:"action"`
	DefaultEffect  string         `json:"default_effect" bson:"default_effect"`
	Rules          []CompiledRule `json:"rules" bson:"rules"`
}
```

Also add `DecisionCheckReq` / `DecisionBatchCheckReq` with `SpaceID`.

**Step 4: Run test to verify it passes**

Run: `go test ./tests/abac -run TestProjectionValidation -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add internal/abac/model/projection_types.go internal/abac/model/projection_req.go internal/abac/model/check_access_req.go internal/abac/model/constants.go tests/abac/projection_validation_test.go
git commit -m "feat: add projection models and decision request validation"
```

## Task 2: Add Projection Repositories and Mongo Indexes

**Files:**
- Modify: `internal/abac/repository/repository.go`
- Modify: `internal/abac/repository/mongo_impl.go`
- Modify: `internal/abac/config/config.go`
- Modify: `cmd/server/main.go`
- Test: `tests/abac/internal_projection_handler_test.go`

**Step 1: Write the failing test**

```go
func TestInternalProjectionHandlers(t *testing.T) {
	t.Run("upsert binding returns 200", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"principal_type": "user",
			"principal_id":   "u_123",
			"grant_tokens":   []string{"space:design:role:member"},
			"binding_version": 42,
		}

		rec := PerformRequest(
			e,
			http.MethodPut,
			"/api/v2/internal/spaces/design/bindings/user/u_123",
			payload,
			map[string]string{"x-user-id": "system_sync"},
		)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./tests/abac -run TestInternalProjectionHandlers -v`  
Expected: FAIL because repository interfaces and routes are missing.

**Step 3: Write minimal implementation**

Extend repositories with methods like:

```go
type ProjectionRepository interface {
	UpsertOrgUserSnapshot(ctx context.Context, snapshot *model.OrgUserSnapshot) error
	GetOrgUserSnapshot(ctx context.Context, userID string) (*model.OrgUserSnapshot, error)
	UpsertSpacePrincipalBinding(ctx context.Context, binding *model.SpacePrincipalBinding) error
	ListSpacePrincipalBindings(ctx context.Context, spaceID string, principals []model.PrincipalRef) ([]*model.SpacePrincipalBinding, error)
	UpsertPolicyRuleSet(ctx context.Context, ruleSet *model.PolicyRuleSet) error
	ActivatePolicyVersion(ctx context.Context, manifest *model.PolicyManifest) error
	GetActivePolicyManifest(ctx context.Context, spaceID string) (*model.PolicyManifest, error)
	GetPolicyRuleSet(ctx context.Context, spaceID string, policyVersion int64, resourceType, action string) (*model.PolicyRuleSet, error)
}
```

Add Mongo collections and indexes for:

- `org_user_snapshots`
- `space_principal_bindings`
- `space_policy_manifests`
- `space_policy_rule_sets`

**Step 4: Run test to verify it passes**

Run: `go test ./tests/abac -run TestInternalProjectionHandlers -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add internal/abac/repository/repository.go internal/abac/repository/mongo_impl.go internal/abac/config/config.go cmd/server/main.go tests/abac/internal_projection_handler_test.go
git commit -m "feat: add projection repositories and mongo indexes"
```

## Task 3: Add Internal Projection APIs and Handlers

**Files:**
- Create: `internal/abac/handler/internal_handler.go`
- Create: `internal/abac/service/projection_service.go`
- Modify: `internal/abac/router/router.go`
- Modify: `internal/abac/handler/error.go`
- Test: `tests/abac/internal_policy_activation_test.go`

**Step 1: Write the failing test**

```go
func TestPolicyActivation(t *testing.T) {
	t.Run("activate policy version returns 200", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		rec := PerformRequest(
			e,
			http.MethodPost,
			"/api/v2/internal/spaces/design/policies/17/activate",
			map[string]interface{}{},
			map[string]string{"x-user-id": "system_sync"},
		)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./tests/abac -run TestPolicyActivation -v`  
Expected: FAIL because internal handlers and routes are missing.

**Step 3: Write minimal implementation**

Add internal APIs:

```go
v2 := e.Group("/api/v2/internal")
v2.PUT("/org-users/batch", h.PutOrgUserSnapshots)
v2.PUT("/spaces/:space_id/bindings/:principal_type/:principal_id", h.PutSpacePrincipalBinding)
v2.PUT("/spaces/:space_id/policies/:policy_version/rule-sets", h.PutPolicyRuleSet)
v2.POST("/spaces/:space_id/policies/:policy_version/activate", h.PostActivatePolicyVersion)
```

Activation must:

- verify rule sets exist
- update `space_policy_manifests`
- atomically switch `active_policy_version`

**Step 4: Run test to verify it passes**

Run: `go test ./tests/abac -run TestPolicyActivation -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add internal/abac/handler/internal_handler.go internal/abac/service/projection_service.go internal/abac/router/router.go internal/abac/handler/error.go tests/abac/internal_policy_activation_test.go
git commit -m "feat: add internal projection and policy activation apis"
```

## Task 4: Extend Effective Subject Resolution with Org Snapshots and Principal Bindings

**Files:**
- Modify: `internal/abac/service/service.go`
- Create: `internal/abac/service/effective_subject.go`
- Modify: `internal/abac/model/types.go`
- Test: `tests/abac/effective_subject_test.go`

**Step 1: Write the failing test**

```go
func TestBuildEffectiveSubject(t *testing.T) {
	t.Run("merges user and org bindings into principal tokens", func(t *testing.T) {
		snapshot := &model.OrgUserSnapshot{
			UserID:      "u_123",
			FunctionIDs: []string{"func_a"},
			DeptID:      "dept_9",
		}

		bindings := []*model.SpacePrincipalBinding{
			{
				SpaceID:       "design",
				PrincipalType: "user",
				PrincipalID:   "u_123",
				GrantTokens:   []string{"space:design:group:reviewers"},
			},
			{
				SpaceID:       "design",
				PrincipalType: "org",
				PrincipalID:   "dept_9",
				GrantTokens:   []string{"space:design:role:member"},
			},
		}

		subject := buildEffectiveSubject("design", "u_123", snapshot, bindings)
		assert.Contains(t, subject.PrincipalTokens, "space:design:role:member")
		assert.Contains(t, subject.PrincipalTokens, "space:design:group:reviewers")
	})
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./tests/abac -run TestBuildEffectiveSubject -v`  
Expected: FAIL because effective-subject resolution does not exist yet.

**Step 3: Write minimal implementation**

Implement logic:

```go
func buildEffectiveSubject(spaceID, userID string, snapshot *model.OrgUserSnapshot, bindings []*model.SpacePrincipalBinding) *model.EffectiveSubject {
	tokens := []string{fmt.Sprintf("space:%s:user:%s", spaceID, userID)}
	if snapshot != nil && snapshot.DeptID != "" {
		tokens = append(tokens, fmt.Sprintf("space:%s:org:%s", spaceID, snapshot.DeptID))
	}
	for _, binding := range bindings {
		tokens = append(tokens, binding.GrantTokens...)
	}
	return &model.EffectiveSubject{
		UserID:          userID,
		PrincipalTokens: dedupe(tokens),
		GroupIDs:        extractGroups(tokens),
	}
}
```

Also update `CheckAccess` and `BatchCheckAccess` to resolve effective subject before OPA evaluation.

**Step 4: Run test to verify it passes**

Run: `go test ./tests/abac -run TestBuildEffectiveSubject -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add internal/abac/service/service.go internal/abac/service/effective_subject.go internal/abac/model/types.go tests/abac/effective_subject_test.go
git commit -m "feat: resolve effective subject from org snapshots and bindings"
```

## Task 5: Extend OPA Input and Rego for Compiled Policy Rule Sets

**Files:**
- Modify: `internal/abac/policy/engine.go`
- Modify: `internal/abac/policy/policies/abac.rego`
- Modify: `internal/abac/model/types.go`
- Test: `tests/abac/compiled_policy_engine_test.go`

**Step 1: Write the failing test**

```go
func TestCompiledPolicyRules(t *testing.T) {
	t.Run("instance deny override beats type allow", func(t *testing.T) {
		resp, err := engine.CheckDecision(ctx, subject, resource, "post_message", ruleSet)
		require.NoError(t, err)
		assert.False(t, resp.Allowed)
	})
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./tests/abac -run TestCompiledPolicyRules -v`  
Expected: FAIL because current OPA input does not support `principal_tokens`, `target_scope`, or `target_resource_id`.

**Step 3: Write minimal implementation**

Extend OPA input:

```go
"subject": map[string]interface{}{
	"user_id":          subject.UserID,
	"status":           subject.Status,
	"org":              subject.Org,
	"principal_tokens": subject.PrincipalTokens,
	"group_ids":        subject.GroupIDs,
},
```

Add Rego helpers for:

- `principal_any`
- `target_scope`
- `target_resource_id`
- `org.dept_id`, `org.sect_id`, `org.function_ids`
- array intersection helper for principal tokens

**Step 4: Run test to verify it passes**

Run: `go test ./tests/abac -run TestCompiledPolicyRules -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add internal/abac/policy/engine.go internal/abac/policy/policies/abac.rego internal/abac/model/types.go tests/abac/compiled_policy_engine_test.go
git commit -m "feat: support compiled rule sets in opa evaluation"
```

## Task 6: Make Decision Lookup Space-Aware and Batch-Efficient

**Files:**
- Modify: `internal/abac/service/service.go`
- Modify: `internal/abac/policy/engine.go`
- Modify: `internal/abac/repository/repository.go`
- Modify: `internal/abac/repository/mongo_impl.go`
- Test: `tests/abac/batch_decision_test.go`

**Step 1: Write the failing test**

```go
func TestBatchDecisionLoadsRuleSetOncePerAction(t *testing.T) {
	mockPolicyRepo := new(MockPolicyRepository)
	mockPolicyRepo.
		On("GetPolicyRuleSet", mock.Anything, "design", int64(17), "document", "read").
		Return(&model.PolicyRuleSet{}, nil).
		Once()

	_, err := svc.BatchCheckAccess(ctx, req)
	require.NoError(t, err)
	mockPolicyRepo.AssertExpectations(t)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./tests/abac -run TestBatchDecisionLoadsRuleSetOncePerAction -v`  
Expected: FAIL because current batch flow still loops and refetches per resource.

**Step 3: Write minimal implementation**

Batch algorithm:

```go
subject := resolveEffectiveSubject(...)
manifest := repo.GetActivePolicyManifest(ctx, req.SpaceID)
grouped := groupResourcesByType(req.Resources)
for resourceType, resources := range grouped {
	ruleSet := repo.GetPolicyRuleSet(ctx, req.SpaceID, manifest.ActivePolicyVersion, resourceType, req.Action)
	for _, resource := range resources {
		result := engine.EvalRuleSet(subject, resource, req.Action, ruleSet)
		results[resource.ResourceID] = result
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./tests/abac -run TestBatchDecisionLoadsRuleSetOncePerAction -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add internal/abac/service/service.go internal/abac/policy/engine.go internal/abac/repository/repository.go internal/abac/repository/mongo_impl.go tests/abac/batch_decision_test.go
git commit -m "feat: optimize batch decisions by space and resource type"
```

## Task 7: Wire Internal Decision APIs and Backward-Compatible Routing

**Files:**
- Modify: `internal/abac/handler/handler.go`
- Modify: `internal/abac/router/router.go`
- Modify: `cmd/server/main.go`
- Test: `tests/abac/internal_decision_api_test.go`

**Step 1: Write the failing test**

```go
func TestInternalDecisionAPI(t *testing.T) {
	t.Run("internal decision check returns 200", func(t *testing.T) {
		rec := PerformRequest(
			e,
			http.MethodPost,
			"/api/v2/internal/decisions/check",
			map[string]interface{}{
				"space_id": "design",
				"action":   "read",
				"resource": map[string]interface{}{
					"resource_id": "doc_1",
					"resource_type": "document",
				},
			},
			map[string]string{"x-user-id": "u_123"},
		)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./tests/abac -run TestInternalDecisionAPI -v`  
Expected: FAIL because internal decision routes are not registered.

**Step 3: Write minimal implementation**

Register routes:

```go
v2.POST("/internal/decisions/check", h.PostInternalDecisionCheck)
v2.POST("/internal/decisions/check/batch", h.PostInternalDecisionBatchCheck)
```

Keep legacy `/api/v1/access/check` intact until upstream clients are migrated.

**Step 4: Run test to verify it passes**

Run: `go test ./tests/abac -run TestInternalDecisionAPI -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add internal/abac/handler/handler.go internal/abac/router/router.go cmd/server/main.go tests/abac/internal_decision_api_test.go
git commit -m "feat: expose internal space-aware decision apis"
```

## Task 8: Add Regression Coverage and Update Docs

**Files:**
- Modify: `docs/abac_system_spec.md`
- Modify: `docs/abac_openapi.yaml`
- Test: `tests/abac/e2e_space_abac_test.go`

**Step 1: Write the failing test**

```go
func TestSpaceABACE2E(t *testing.T) {
	t.Run("org binding grants member role and channel override denies contributor", func(t *testing.T) {
		// Seed snapshot, bindings, manifest, rule set, then assert final decision.
		assert.True(t, canReadDocument)
		assert.False(t, canPostToGeneral)
	})
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./tests/abac -run TestSpaceABACE2E -v`  
Expected: FAIL until snapshots, bindings, compiled rules, and decision flow work together.

**Step 3: Write minimal implementation**

Document:

- internal projection APIs
- decision API contract
- required collections and indexes
- new subject and rule-set input format

Add end-to-end test coverage for:

- user binding + org binding merge
- group rule on restricted resource
- instance deny override on channel
- batch check reusing active rule sets

**Step 4: Run test to verify it passes**

Run: `go test ./tests/abac -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add docs/abac_system_spec.md docs/abac_openapi.yaml tests/abac/e2e_space_abac_test.go
git commit -m "docs: update abac spec for space-scoped compiled policy flow"
```

## Implementation Order

1. Models and validation
2. Repositories and indexes
3. Projection APIs
4. Effective subject resolution
5. OPA/Rego compiled policy support
6. Batch decision optimization
7. Internal decision routing
8. Documentation and regression coverage

## Risk Notes

- `OrgUser` daily sync can create stale authorization for up to one sync interval.
- Policy activation must be atomic or mixed-version decisions will occur.
- Group and org grants must remain clearly separated from policy rules or the model will become impossible to debug.
- Backward compatibility for legacy `/api/v1/access/check` must be decided before removing old endpoints.

## Definition of Done

- Internal projection APIs exist and are tested.
- Active compiled policy can be published and atomically activated.
- Decision flow resolves effective subject from org snapshots plus principal bindings.
- OPA supports principal tokens, org attributes, and instance overrides.
- Batch decisions reuse loaded rule sets.
- All new tests pass under `go test ./tests/abac -v`.

## Handoff Notes

- Use the design doc first: `docs/plans/2026-03-29-space-abac-authz-design.md`
- This plan assumes a future Space BE compiler will already exist or be built in parallel.
- Do not implement FE capability APIs in this repo; only provide the internal decision capabilities they depend on.

Plan complete and saved to `docs/plans/2026-03-29-space-abac-authz-implementation-plan.md`. Two execution options:

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

Which approach?
