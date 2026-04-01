# ABAC Rego Evaluator Upgrade Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade the current ABAC engine from the legacy `role/group_ids + conditions` model into the design-doc generic evaluator that consumes `space`-scoped rule sets, principal tokens, and instance-aware policy projections.

**Architecture:** Keep `Space BE` as the compiler and policy authoring layer, keep `Auth Platform` as the runtime policy store plus OPA decision service, and upgrade the evaluator so Rego consumes grouped `rule_set` data instead of ad hoc flat rule lists. The migration should separate one-time genericization work from future resource onboarding, so ordinary new `resource_type`s become data changes instead of Rego changes.

**Tech Stack:** Go, Echo, MongoDB repository layer, OPA/Rego, testify

---

## Scope

This plan only covers the evaluator-side upgrade inside this repo:

- runtime data model changes needed by the design
- repository/query changes for active manifests and grouped rule sets
- OPA input shape changes
- `abac.rego` rewrite into a generic rule-set evaluator
- test upgrades for the new decision semantics

This plan does **not** implement:

- `Space BE` policy compiler
- `Space BE` projection publishing APIs
- `OrgUser` sync jobs
- FE capability APIs

Those are upstream dependencies. This plan prepares `Auth Platform` to consume the design-doc projection model once those upstream pieces exist.

## Current Gaps

Current code in:

- [engine.go](/C:/Users/wenmo/work/rbac7/internal/abac/policy/engine.go)
- [abac.rego](/C:/Users/wenmo/work/rbac7/internal/abac/policy/policies/abac.rego)
- [types.go](/C:/Users/wenmo/work/rbac7/internal/abac/model/types.go)
- [repository.go](/C:/Users/wenmo/work/rbac7/internal/abac/repository/repository.go)

is still based on the legacy evaluator model:

- subject identity is mainly `role`, `group_ids`, `custom_attrs`
- rule lookup is `FindPolicyRules(resourceType, action)`
- OPA input receives flat `input.rules`
- Rego does not understand:
  - `principal_tokens`
  - `principal_any`
  - `target_scope`
  - `target_resource_id`
  - `default_effect`
  - grouped `rule_set`
  - active `policy_version`

The main architectural goal of this upgrade is:

- **one-time evaluator genericization now**
- **no repeated Rego edits for ordinary new `resource_type`s later**

## Target End State

After this upgrade, the runtime decision path should look like:

1. request includes `space_id`, `resource_type`, `action`, and runtime resource attrs
2. service/engine resolves subject data into:
   - `user_id`
   - `org`
   - `principal_tokens`
   - `group_ids`
3. engine loads:
   - active `space_policy_manifest`
   - one grouped `space_policy_rule_set`
4. OPA evaluates:
   - `target_scope`
   - `principal_any`
   - subject conditions
   - resource conditions
   - deny-over-allow at equal priority
   - `default_effect`
5. response returns:
   - `allow/deny`
   - matched `rule_id`
   - useful reason text

## Migration Strategy

Recommended rollout:

1. add new runtime types alongside current legacy types
2. add new repository methods without deleting old ones
3. add new engine path that can evaluate grouped `rule_set`s
4. rewrite Rego to support the new input
5. switch service paths to the new evaluator contract
6. remove legacy rule-loading path only after new tests pass

This keeps the blast radius smaller and makes rollback easier.

## Task 1: Introduce Target Runtime Types

**Files:**
- Modify: [types.go](/C:/Users/wenmo/work/rbac7/internal/abac/model/types.go)
- Create: `C:/Users/wenmo/work/rbac7/internal/abac/model/policy_projection.go`
- Test: [engine_test.go](/C:/Users/wenmo/work/rbac7/internal/abac/policy/engine_test.go)

**Why this task exists**

The current model only knows about `Subject`, `ResourceAttrs`, and flat `PolicyRule`. The design requires new runtime documents and new evaluator-facing shapes.

**Add these model types**

- `PolicyManifest`
  - `space_id`
  - `active_policy_version`
  - `compiler_version`
  - `source_matrix_version`
  - `checksum`
  - `status`
- `PolicyRuleSet`
  - `space_id`
  - `policy_version`
  - `resource_type`
  - `action`
  - `default_effect`
  - `rules`
- `CompiledRule`
  - `rule_id`
  - `source_kind`
  - `source_ref`
  - `effect`
  - `priority`
  - `target_scope`
  - `target_resource_id`
  - `principal_any`
  - `subject_conditions`
  - `resource_conditions`
  - `env_conditions`
  - `enabled`
- `EffectiveSubject`
  - `user_id`
  - `status`
  - `org`
  - `principal_tokens`
  - `group_ids`

**Also extend existing runtime request shapes**

- `ResourceAttrs` must include `space_id`
- keep `resource_parent_id`
- keep existing resource attrs that still map cleanly into the design

**Verification target**

Add or update tests so engine tests can build a new-style evaluator input without abusing legacy `PolicyRule`.

## Task 2: Extend Repository Contracts for Projection-Based Runtime Reads

**Files:**
- Modify: [repository.go](/C:/Users/wenmo/work/rbac7/internal/abac/repository/repository.go)
- Modify: [mongo_impl.go](/C:/Users/wenmo/work/rbac7/internal/abac/repository/mongo_impl.go)
- Test: `C:/Users/wenmo/work/rbac7/internal/abac/repository/mongo_impl_test.go` or `C:/Users/wenmo/work/rbac7/tests/abac/policy_projection_repository_test.go`

**Why this task exists**

The current repository contract only supports:

- `FindPolicyRules(resourceType, action)`

That is not sufficient for the design runtime path.

**Add repository methods for runtime reads**

- `GetActivePolicyManifest(ctx, spaceID string) (*model.PolicyManifest, error)`
- `GetPolicyRuleSet(ctx, spaceID string, policyVersion int, resourceType, action string) (*model.PolicyRuleSet, error)`

If batching is planned in the same phase, also add:

- `GetPolicyRuleSets(ctx, spaceID string, policyVersion int, pairs []RuleSetKey) ([]*model.PolicyRuleSet, error)`

Optional if binding resolution is moved into this repo later:

- `GetPrincipalBindings(...)`
- `GetOrgSnapshot(...)`

For this evaluator plan, those can remain future-facing if subject resolution is still stubbed.

**Mongo storage requirements**

- collection for `space_policy_manifests`
- collection for `space_policy_rule_sets`
- indexes:
  - `(space_id)` unique for manifest
  - `(space_id, policy_version, resource_type, action)` unique for rule sets
  - `(space_id, resource_type, action)` for active-path lookups if needed

**Verification target**

Repository tests should prove:

- active manifest can be fetched by `space_id`
- grouped rule set can be fetched by exact `(space_id, policy_version, resource_type, action)`
- missing rule sets return a clean not-found path

## Task 3: Refactor Engine Input Builder to the Design-Doc Shape

**Files:**
- Modify: [engine.go](/C:/Users/wenmo/work/rbac7/internal/abac/policy/engine.go)
- Modify: [types.go](/C:/Users/wenmo/work/rbac7/internal/abac/model/types.go)
- Test: [engine_test.go](/C:/Users/wenmo/work/rbac7/internal/abac/policy/engine_test.go)

**Why this task exists**

Current engine behavior:

- loads flat rules by `resource_type + action`
- converts them into `input.rules`
- passes old subject shape into OPA

Target engine behavior:

- requires `space_id`
- loads active manifest
- loads one grouped `rule_set`
- builds `input.subject`, `input.resource`, `input.action`, `input.rule_set`

**Concrete code changes**

Replace legacy `OPAInput` shape with a design-aligned shape:

- `subject`
  - `user_id`
  - `status`
  - `org`
  - `principal_tokens`
  - `group_ids`
  - `custom_attrs` only if still needed
- `resource`
  - `space_id`
  - `resource_id`
  - `resource_type`
  - `resource_parent_id`
  - `owner_id`
  - `classification` / `visibility` if adopted now
  - `allowed_group_ids`
  - `denied_group_ids`
- `action`
- `rule_set`

**Engine responsibilities**

- validate `resource.space_id` exists
- fetch active manifest by `space_id`
- fetch grouped `rule_set` by:
  - `space_id`
  - `active_policy_version`
  - `resource_type`
  - `action`
- build new input document
- parse richer OPA output:
  - `allow`
  - `reason`
  - optionally `matched_rule_ids`

**Verification target**

Engine tests should cover:

- no manifest => default deny
- no rule set => use `default_effect`
- instance rule beats type rule on higher priority
- deny beats allow on equal priority

## Task 4: Rewrite `abac.rego` into a Generic Rule-Set Evaluator

**Files:**
- Modify: [abac.rego](/C:/Users/wenmo/work/rbac7/internal/abac/policy/policies/abac.rego)
- Test: [engine_test.go](/C:/Users/wenmo/work/rbac7/internal/abac/policy/engine_test.go)

**Why this task exists**

This is the core one-time genericization step. Without it, new `resource_type`s will keep leaking evaluator changes into the Rego layer.

**Replace legacy assumptions**

Remove the assumption that a rule is matched only by:

- `r.resource_type == input.resource.resource_type`
- `r.action == input.action`

Because those now belong to the grouped `rule_set` and rule target semantics.

**Add these evaluator primitives**

1. `target_match(r)`
- support `target_scope == "type"`
- support `target_scope == "instance"`

2. `principal_match(r)`
- match `r.principal_any` against `input.subject.principal_tokens`

3. `subject_conditions_match(...)`
- evaluate `subject_conditions`

4. `resource_conditions_match(...)`
- evaluate `resource_conditions`

5. `env_conditions_match(...)`
- can initially be pass-through if `env_conditions` is empty

6. `winning_rules`
- highest priority wins
- same priority prefers `deny`

7. `default_effect`
- when no rules match, evaluate `input.rule_set.default_effect`

**New field resolvers required**

Subject side:

- `principal_tokens`
- `group_ids`
- `status`
- `org.*`
- `custom.*` if retained

Resource side:

- `space_id`
- `resource_id`
- `resource_type`
- `resource_parent_id`
- `owner_id`
- `classification`
- `visibility`
- `allowed_group_ids`
- `denied_group_ids`
- `custom.*`

**Keep or remove current group allow/deny helper logic**

Decision:

- either treat `allowed_group_ids / denied_group_ids` as resource condition helpers in Rego
- or migrate them into generic `resource_conditions`

Recommendation:

- keep them short-term for backward compatibility
- document whether they remain first-class or are folded into generic conditions later

**Verification target**

Add direct engine tests proving:

- ordinary new `resource_type = asset` works with no Rego changes beyond this one rewrite
- `channel` instance override works through `target_scope = instance`
- group-based allow works through `principal_any`

## Task 5: Upgrade Batch Evaluation Behavior

**Files:**
- Modify: [service.go](/C:/Users/wenmo/work/rbac7/internal/abac/service/service.go)
- Modify: [engine.go](/C:/Users/wenmo/work/rbac7/internal/abac/policy/engine.go)
- Test: [post_check_access_test.go](/C:/Users/wenmo/work/rbac7/tests/abac/post_check_access_test.go)
- Test: `C:/Users/wenmo/work/rbac7/tests/abac/post_check_access_batch_test.go` if created

**Why this task exists**

The design relies on `resource-instance-capabilities` being heavy but still controlled. That only works if batch checks do not repeat static work for each resource.

**Required behavior**

- resolve subject once per batch
- fetch active manifest once per batch / `space_id`
- fetch grouped `rule_set` once per distinct `(resource_type, action)` pair
- evaluate per resource in memory

**Service changes**

Current `BatchCheckAccess` loops and calls single-check repeatedly.

Refactor it so the batch path can:

- group resources by `(space_id, resource_type)`
- reuse the same `rule_set`
- avoid repeated repository hits

**Verification target**

Tests should prove:

- batch path returns same decisions as repeated single-check
- repository hit count is reduced for repeated `(resource_type, action)` pairs

## Task 6: Update External Request Validation and Compatibility Rules

**Files:**
- Modify: [check_access_req.go](/C:/Users/wenmo/work/rbac7/internal/abac/model/check_access_req.go)
- Modify: [handler.go](/C:/Users/wenmo/work/rbac7/internal/abac/handler/handler.go)
- Modify: [service.go](/C:/Users/wenmo/work/rbac7/internal/abac/service/service.go)
- Test: [post_check_access_test.go](/C:/Users/wenmo/work/rbac7/tests/abac/post_check_access_test.go)

**Why this task exists**

The design runtime path depends on `space_id`. Current request validation does not require it.

**Required changes**

- require `resource.space_id` for new-style checks
- keep `subject_id` behavior as-is unless internal service auth replaces it later
- document whether legacy calls without `space_id` are:
  - rejected immediately
  - or temporarily mapped to a compatibility path

Recommendation:

- make `space_id` required as part of this upgrade
- fail fast with clear validation errors

**Verification target**

Tests should cover:

- missing `space_id` => `400`
- valid `space_id` + rule set => expected decision

## Task 7: Replace Legacy Policy Tests with Design-Oriented Evaluator Tests

**Files:**
- Modify: [engine_test.go](/C:/Users/wenmo/work/rbac7/internal/abac/policy/engine_test.go)
- Modify: [post_check_access_test.go](/C:/Users/wenmo/work/rbac7/tests/abac/post_check_access_test.go)
- Create: `C:/Users/wenmo/work/rbac7/tests/abac/post_check_access_batch_test.go`

**Why this task exists**

Current tests mostly verify:

- legacy `role` checks
- legacy `conditions.subject/resource`
- direct `FindPolicyRules(resourceType, action)` behavior

Those are no longer sufficient for the target design.

**Minimum new test cases**

1. `asset.read` works with type-level allow
2. `channel.general.post_message` denied by default effect
3. `channel.incidents.post_message` allowed by instance override
4. equal-priority allow/deny => deny wins
5. `org` or `principal_tokens` based match succeeds
6. unknown rule set => default deny
7. batch evaluation reuses rule data for same resource type/action

**Keep one temporary regression set**

Retain a small number of old tests only if they still validate generic condition operators.

## Task 8: Document the New Evaluator Contract

**Files:**
- Modify: [2026-03-29-space-abac-authz-design.md](/C:/Users/wenmo/work/rbac7/docs/plans/2026-03-29-space-abac-authz-design.md)
- Modify: [2026-03-31-space-abac-authz-flows-zh.md](/C:/Users/wenmo/work/rbac7/docs/plans/2026-03-31-space-abac-authz-flows-zh.md)
- Create: `C:/Users/wenmo/work/rbac7/docs/plans/2026-04-01-abac-rego-evaluator-contract.md`

**Why this task exists**

The evaluator contract is the boundary that prevents future resource onboarding from forcing Rego changes.

**Document clearly**

- required input shape to OPA
- supported rule fields
- supported operators
- which changes require Rego edits
- which changes are data-only

This document becomes the guardrail for all future resource onboarding.

## Recommended Execution Order

1. Task 1: runtime types
2. Task 2: repository contracts
3. Task 3: engine input builder
4. Task 4: Rego rewrite
5. Task 6: request validation
6. Task 5: batch optimization
7. Task 7: tests
8. Task 8: documentation

## Definition of Done

This upgrade is complete only when all of the following are true:

- `abac.rego` consumes grouped `rule_set` input rather than flat legacy rules
- engine loads active manifest + grouped rule set by `space_id`
- request validation requires `space_id`
- batch checks reuse subject resolution and grouped rule sets
- tests prove a new ordinary `resource_type` works without Rego changes
- docs explicitly distinguish:
  - data-only onboarding changes
  - evaluator semantic changes that require Rego work

## Final Recommendation

Treat this upgrade as a **one-time platform investment**.

If the team skips this genericization step, every future `resource_type` onboarding risks leaking policy semantics into Rego and recreating the same coupling problem. If the team completes this upgrade cleanly, future onboarding should mostly become:

- register contract
- update template / `space` policy
- publish compiled `rule_sets`

instead of “edit Rego again”.
