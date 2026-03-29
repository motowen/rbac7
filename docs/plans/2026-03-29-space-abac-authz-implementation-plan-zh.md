# Space ABAC Auth Platform 實作計畫

> **給 Claude:** 必要的子技能 (REQUIRED SUB-SKILL): 使用 `superpowers:executing-plans` 來逐項任務 (task-by-task) 地實作此計畫。

**目標:** 升級此 auth platform (授權平台) repository 以支援空間範圍的 ABAC 決策，這些決策由組織快照 (org snapshots)、空間主體綁定 (space principal bindings)、編譯的策略規則集 (compiled policy rule sets) 提供支援，並實現高效率的批次決策評估。

**架構:** 保持 OPA/Rego 為靜態且通用的狀態。接收來自上游系統的投影資料 (projection data)，將其儲存在本地的 MongoDB 中。由組織快照加上空間主體綁定來解析出有效主體 (effective subject)，接著透過 `(space_id, resource_type, action)` 載入當前活躍的編譯規則集，然後在 OPA 中評估它們。這個 repository 將不會負責 Space BE 權威策略的編輯或資源查詢；它只負責投影資料的接收與決策的執行。

**技術堆疊:** Go, Echo, MongoDB, OPA/Rego, Testify, 以及現存的 `tests/abac` 測試框架。

---

## 範圍 (Scope)

此計畫僅涵蓋本 repository 內的變更。

超出本 repo 範圍的項目有：

- Space BE 的權威矩陣編輯 UI
- Space BE 的編譯器實作
- FE 的能力聚合端點 (capability aggregation endpoints)
- Resource BE 候選資源的查詢

需要上游整合的合約 (Integration contracts)：

- Space BE 發布 `space_principal_bindings`
- Space BE 發布已編譯的 `space_policy_rule_sets` 並啟用特定的 `policy_version`
- 組織同步任務發布 `org_user_snapshots`
- Space BE / Resource BE 呼叫內部決策 API

## 任務 1: 新增投影模型與請求驗證 (Add Projection Models and Request Validation)

**相關檔案:**
- 建立: `internal/abac/model/projection_types.go`
- 建立: `internal/abac/model/projection_req.go`
- 修改: `internal/abac/model/check_access_req.go`
- 修改: `internal/abac/model/constants.go`
- 測試: `tests/abac/projection_validation_test.go`

**步驟 1: 撰寫失敗的測試 (Write the failing test)**

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

**步驟 2: 執行測試並驗證其失敗**

執行: `go test ./tests/abac -run TestProjectionValidation -v`  
預期結果: 失敗 (FAIL)，因為新的投影請求類型尚未存在。

**步驟 3: 撰寫最小實作 (Write minimal implementation)**

新增模型類型 (model types)：

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

同樣在 `DecisionCheckReq` / `DecisionBatchCheckReq` 中加入 `SpaceID`。

**步驟 4: 執行測試並驗證其通過**

執行: `go test ./tests/abac -run TestProjectionValidation -v`  
預期結果: 通過 (PASS)

**步驟 5: 提交 (Commit)**

```bash
git add internal/abac/model/projection_types.go internal/abac/model/projection_req.go internal/abac/model/check_access_req.go internal/abac/model/constants.go tests/abac/projection_validation_test.go
git commit -m "feat: add projection models and decision request validation"
```

## 任務 2: 新增投影 Repositories 與 Mongo 索引 (Add Projection Repositories and Mongo Indexes)

**相關檔案:**
- 修改: `internal/abac/repository/repository.go`
- 修改: `internal/abac/repository/mongo_impl.go`
- 修改: `internal/abac/config/config.go`
- 修改: `cmd/server/main.go`
- 測試: `tests/abac/internal_projection_handler_test.go`

**步驟 1: 撰寫失敗的測試**

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

**步驟 2: 執行測試並驗證其失敗**

執行: `go test ./tests/abac -run TestInternalProjectionHandlers -v`  
預期結果: 失敗 (FAIL)，因為儲存庫介面與路由缺失。

**步驟 3: 撰寫最小實作**

擴展 repositories 方法，如：

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

為以下項目新增 Mongo collections 及 indexes：

- `org_user_snapshots`
- `space_principal_bindings`
- `space_policy_manifests`
- `space_policy_rule_sets`

**步驟 4: 執行測試並驗證其通過**

執行: `go test ./tests/abac -run TestInternalProjectionHandlers -v`  
預期結果: 通過 (PASS)

**步驟 5: 提交**

```bash
git add internal/abac/repository/repository.go internal/abac/repository/mongo_impl.go internal/abac/config/config.go cmd/server/main.go tests/abac/internal_projection_handler_test.go
git commit -m "feat: add projection repositories and mongo indexes"
```

## 任務 3: 新增內部投影 APIs 與 Handlers (Add Internal Projection APIs and Handlers)

**相關檔案:**
- 建立: `internal/abac/handler/internal_handler.go`
- 建立: `internal/abac/service/projection_service.go`
- 修改: `internal/abac/router/router.go`
- 修改: `internal/abac/handler/error.go`
- 測試: `tests/abac/internal_policy_activation_test.go`

**步驟 1: 撰寫失敗的測試**

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

**步驟 2: 執行測試並驗證其失敗**

執行: `go test ./tests/abac -run TestPolicyActivation -v`  
預期結果: 失敗 (FAIL)，因為缺乏內部 handlers 與 routes。

**步驟 3: 撰寫最小實作**

建立內部 APIs：

```go
v2 := e.Group("/api/v2/internal")
v2.PUT("/org-users/batch", h.PutOrgUserSnapshots)
v2.PUT("/spaces/:space_id/bindings/:principal_type/:principal_id", h.PutSpacePrincipalBinding)
v2.PUT("/spaces/:space_id/policies/:policy_version/rule-sets", h.PutPolicyRuleSet)
v2.POST("/spaces/:space_id/policies/:policy_version/activate", h.PostActivatePolicyVersion)
```

啟用機制 (Activation) 必須：

- 驗證 rule sets 是否存在
- 更新 `space_policy_manifests`
- 原子地切換 `active_policy_version`

**步驟 4: 執行測試並驗證其通過**

執行: `go test ./tests/abac -run TestPolicyActivation -v`  
預期結果: 通過 (PASS)

**步驟 5: 提交**

```bash
git add internal/abac/handler/internal_handler.go internal/abac/service/projection_service.go internal/abac/router/router.go internal/abac/handler/error.go tests/abac/internal_policy_activation_test.go
git commit -m "feat: add internal projection and policy activation apis"
```

## 任務 4: 利用組織快照與主體綁定擴充有效主體解析 (Extend Effective Subject Resolution with Org Snapshots and Principal Bindings)

**相關檔案:**
- 修改: `internal/abac/service/service.go`
- 建立: `internal/abac/service/effective_subject.go`
- 修改: `internal/abac/model/types.go`
- 測試: `tests/abac/effective_subject_test.go`

**步驟 1: 撰寫失敗的測試**

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

**步驟 2: 執行測試並驗證其失敗**

執行: `go test ./tests/abac -run TestBuildEffectiveSubject -v`  
預期結果: 失敗 (FAIL)，因為有效主體解析機制尚未建立。

**步驟 3: 撰寫最小實作**

實作邏輯：

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

同時更新 `CheckAccess` 與 `BatchCheckAccess`，以便在進行 OPA 評估之前先解析出有效主體。

**步驟 4: 執行測試並驗證其通過**

執行: `go test ./tests/abac -run TestBuildEffectiveSubject -v`  
預期結果: 通過 (PASS)

**步驟 5: 提交**

```bash
git add internal/abac/service/service.go internal/abac/service/effective_subject.go internal/abac/model/types.go tests/abac/effective_subject_test.go
git commit -m "feat: resolve effective subject from org snapshots and bindings"
```

## 任務 5: 針對編譯的策略規則集擴展 OPA 輸入及 Rego (Extend OPA Input and Rego for Compiled Policy Rule Sets)

**相關檔案:**
- 修改: `internal/abac/policy/engine.go`
- 修改: `internal/abac/policy/policies/abac.rego`
- 修改: `internal/abac/model/types.go`
- 測試: `tests/abac/compiled_policy_engine_test.go`

**步驟 1: 撰寫失敗的測試**

```go
func TestCompiledPolicyRules(t *testing.T) {
	t.Run("instance deny override beats type allow", func(t *testing.T) {
		resp, err := engine.CheckDecision(ctx, subject, resource, "post_message", ruleSet)
		require.NoError(t, err)
		assert.False(t, resp.Allowed)
	})
}
```

**步驟 2: 執行測試並驗證其失敗**

執行: `go test ./tests/abac -run TestCompiledPolicyRules -v`  
預期結果: 失敗 (FAIL)，因為目前的 OPA 輸入不支援 `principal_tokens`、`target_scope` 或 `target_resource_id`。

**步驟 3: 撰寫最小實作**

擴充 OPA 輸入：

```go
"subject": map[string]interface{}{
	"user_id":          subject.UserID,
	"status":           subject.Status,
	"org":              subject.Org,
	"principal_tokens": subject.PrincipalTokens,
	"group_ids":        subject.GroupIDs,
},
```

新增 Rego 的 helper：

- `principal_any`
- `target_scope`
- `target_resource_id`
- `org.dept_id`, `org.sect_id`, `org.function_ids`
- 用於主體權杖的陣列交集 (array intersection) helper

**步驟 4: 執行測試並驗證其通過**

執行: `go test ./tests/abac -run TestCompiledPolicyRules -v`  
預期結果: 通過 (PASS)

**步驟 5: 提交**

```bash
git add internal/abac/policy/engine.go internal/abac/policy/policies/abac.rego internal/abac/model/types.go tests/abac/compiled_policy_engine_test.go
git commit -m "feat: support compiled rule sets in opa evaluation"
```

## 任務 6: 讓決策尋找能支援空間感知機制與效率批次作業 (Make Decision Lookup Space-Aware and Batch-Efficient)

**相關檔案:**
- 修改: `internal/abac/service/service.go`
- 修改: `internal/abac/policy/engine.go`
- 修改: `internal/abac/repository/repository.go`
- 修改: `internal/abac/repository/mongo_impl.go`
- 測試: `tests/abac/batch_decision_test.go`

**步驟 1: 撰寫失敗的測試**

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

**步驟 2: 執行測試並驗證其失敗**

執行: `go test ./tests/abac -run TestBatchDecisionLoadsRuleSetOncePerAction -v`  
預期結果: 失敗 (FAIL)，因為目前的批次處理流程在每個資源下仍會迴圈處理和重新抓取資料。

**步驟 3: 撰寫最小實作**

批次處理演算法：

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

**步驟 4: 執行測試並驗證其通過**

執行: `go test ./tests/abac -run TestBatchDecisionLoadsRuleSetOncePerAction -v`  
預期結果: 通過 (PASS)

**步驟 5: 提交**

```bash
git add internal/abac/service/service.go internal/abac/policy/engine.go internal/abac/repository/repository.go internal/abac/repository/mongo_impl.go tests/abac/batch_decision_test.go
git commit -m "feat: optimize batch decisions by space and resource type"
```

## 任務 7: 銜接內部決策 API 與向下相容的路由 (Wire Internal Decision APIs and Backward-Compatible Routing)

**相關檔案:**
- 修改: `internal/abac/handler/handler.go`
- 修改: `internal/abac/router/router.go`
- 修改: `cmd/server/main.go`
- 測試: `tests/abac/internal_decision_api_test.go`

**步驟 1: 撰寫失敗的測試**

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

**步驟 2: 執行測試並驗證其失敗**

執行: `go test ./tests/abac -run TestInternalDecisionAPI -v`  
預期結果: 失敗 (FAIL)，因為尚未註冊內部決策路由。

**步驟 3: 撰寫最小實作**

註冊路由：

```go
v2.POST("/internal/decisions/check", h.PostInternalDecisionCheck)
v2.POST("/internal/decisions/check/batch", h.PostInternalDecisionBatchCheck)
```

在所有上游客戶端遷移完畢前，請保留原本的 `/api/v1/access/check` (向後相容)。

**步驟 4: 執行測試並驗證其通過**

執行: `go test ./tests/abac -run TestInternalDecisionAPI -v`  
預期結果: 通過 (PASS)

**步驟 5: 提交**

```bash
git add internal/abac/handler/handler.go internal/abac/router/router.go cmd/server/main.go tests/abac/internal_decision_api_test.go
git commit -m "feat: expose internal space-aware decision apis"
```

## 任務 8: 加入回歸測試覆蓋率與文件更新 (Add Regression Coverage and Update Docs)

**相關檔案:**
- 修改: `docs/abac_system_spec.md`
- 修改: `docs/abac_openapi.yaml`
- 測試: `tests/abac/e2e_space_abac_test.go`

**步驟 1: 撰寫失敗的測試**

```go
func TestSpaceABACE2E(t *testing.T) {
	t.Run("org binding grants member role and channel override denies contributor", func(t *testing.T) {
		// 準備(Seed) 快照、綁定、清單、規則集，然後斷言最後的決策結果
		assert.True(t, canReadDocument)
		assert.False(t, canPostToGeneral)
	})
}
```

**步驟 2: 執行測試並驗證其失敗**

執行: `go test ./tests/abac -run TestSpaceABACE2E -v`  
預期結果: 失敗 (FAIL)，直到快照、綁定、編譯規則與決策流程能協同運作才能通過。

**步驟 3: 撰寫最小實作**

建立文件記錄：

- 內部投影 APIs
- 決策 API 合約
- 需要的 mongo collections 和 indexes
- 全新的主體和規則集輸入格式

加入點對點的測試覆蓋率：

- 驗證「使用者綁定」加上「組織綁定」的資料合併行為
- 驗證群組對受限資源的操作規則
- 驗證頻道的實例 deny 覆寫
- 驗證可重複利用當前活動規則集的批次檢查

**步驟 4: 執行測試並驗證其通過**

執行: `go test ./tests/abac -v`  
預期結果: 通過 (PASS)

**步驟 5: 提交**

```bash
git add docs/abac_system_spec.md docs/abac_openapi.yaml tests/abac/e2e_space_abac_test.go
git commit -m "docs: update abac spec for space-scoped compiled policy flow"
```

## 實作順序 (Implementation Order)

1. Models 和驗證 (Validation)
2. Repositories 和 Indexes
3. 投影 APIs (Projection APIs)
4. 有效主體解析 (Effective subject resolution)
5. OPA/Rego 編譯策略支援
6. 批次決策優化
7. 內部決策路由機制
8. 文件更新與回歸測試

## 風險筆記 (Risk Notes)

- `OrgUser` 每日同步機制最多會產生一個同步週期的過期授權狀態。
- 策略啟用必須原子化，否則會出現混合版本策略的決策行為發生。
- 群組和組織對應的 authorizations 必須與策略規則明確隔離，否則這套模型在實務上會變得難以 debug。
- 在移除舊路由前，必須先確定 `/api/v1/access/check` 的向下相容處理。

## 完成定義 (Definition of Done)

- 內部投影 APIs 皆已存在並測試通過。
- 活躍編譯策略能夠正常發布並具有原子化變更機制。
- 決策流程會依據「組織快照 + 主體綁定」解析出有效主體。
- OPA 支援主體權杖 (principal tokens)、組織屬性，以及實例的覆寫機制 (instance overrides)。
- 批次決策已能重複利用成功載入的規則集。
- 執行 `go test ./tests/abac -v` 下的所有新測試都能獲判 PASS。

## 交接筆記 (Handoff Notes)

- 優先參考設計文件：`docs/plans/2026-03-29-space-abac-authz-design.md`
- 本計畫基於以下假設：未來的 Space BE Compiler 將已經存在或即將同步建造中。
- 不要在本 repo 實作上游 FE 的 capability API 端點；只需要專注提供 FE 依賴的底層內部決策支援即可。

計畫撰寫完成並儲存至 `docs/plans/2026-03-29-space-abac-authz-implementation-plan.md`。有兩種執行選項方案：

**1. 基於單一子 Agent (本次會話)** - 每項任務會啟動新的子 Agent 協助，在任務之間進行 Code review 來快速迭代。

**2. 獨立並行的 Session** - 另外開啟一個掛載 `executing-plans` 的全新會話，並設定不同斷點進行批次執行。

你比較想要使用哪一種方法？
