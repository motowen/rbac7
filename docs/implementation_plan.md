# NATS Auth Callout + NATS Messaging 整合至 RBAC Service

將現有的 HTTP-only RBAC service 擴展為支援 **NATS Auth Callout**（使用者連線認證授權）和 **NATS Request-Reply**（業務 API 互動）的雙通道架構。Service/Repository/Policy 層不需修改，只需新增 NATS transport 層。

## User Review Required

> [!IMPORTANT]
> **RBAC 角色 → NATS Subject 權限的映射設計** 是最關鍵的架構決策。以下計畫提供了預設映射方案，但實際映射需要根據 FE 的 subject 命名規則來調整。請確認 FE 預期使用的 NATS subject 格式。

> [!WARNING]
> **連線時權限 vs 請求時權限**：NATS Auth Callout 在**連線時**決定權限（靜態），但現有 RBAC middleware 在**每次請求時**動態檢查。計畫中採用「雙層檢查」策略 — Auth Callout 做粗粒度授權，NATS handlers 做細粒度 RBAC 檢查。如果你希望改為純 Auth Callout 靜態權限，請告知。

---

## Proposed Changes

### Phase 1: 基礎建設 — Config + NATS 連線

#### [MODIFY] [config.go](file:///c:/Users/wenmo/work/rbac7/internal/rbac/config/config.go)

新增 NATS 相關設定欄位：

```go
type Config struct {
    // ... 現有欄位 ...

    // NATS
    NATSEnabled       bool   // 是否啟用 NATS（預設 false，向後相容）
    NATSURL           string // NATS server URL (e.g., "nats://localhost:4222")
    NATSAuthUser      string // Auth Callout 服務連線用的 user
    NATSAuthPassword  string // Auth Callout 服務連線用的 password
    NATSAccountSeed   string // Account private key seed (SA...) for signing JWTs
    NATSEncryptionKey string // 可選，XKey curve seed for encrypted callout
}
```

環境變數對照：

| 變數 | 預設值 | 說明 |
|---|---|---|
| `NATS_ENABLED` | `false` | 是否啟用 NATS |
| `NATS_URL` | `nats://localhost:4222` | NATS Server URL |
| `NATS_AUTH_USER` | `auth` | Auth callout service 連線 user |
| `NATS_AUTH_PASSWORD` | _(必填)_ | Auth callout service 連線 password |
| `NATS_ACCOUNT_SEED` | _(必填)_ | Account NKey Seed (`SA...`) |
| `NATS_ENCRYPTION_KEY` | _(可選)_ | Curve NKey Seed (`SX...`) |

---

### Phase 2: Auth Callout — 認證授權服務

#### [NEW] [auth_callout.go](file:///c:/Users/wenmo/work/rbac7/internal/rbac/nats/auth_callout.go)

使用 `synadia-io/callout.go` 函式庫，核心邏輯：

```go
// AuthCalloutService wraps the callout library with RBAC integration
type AuthCalloutService struct {
    svc        *callout.AuthorizationService
    rbacSvc    service.RBACService
    accountKP  nkeys.KeyPair
}

// authorizer 是給 callout.go 的 AuthorizerFn callback
func (a *AuthCalloutService) authorizer(req *jwt.AuthorizationRequest) (string, error) {
    // 1. 從 req.ConnectOptions.Token 或 req.ConnectOptions.Username 取得使用者身分
    //    FE 連線時會帶 token 或 username，這裡解析出 userID
    userID := extractUserID(req)
    if userID == "" {
        return "", callout.ErrAbortRequest // 拒絕：延遲回應
    }

    // 2. 查詢使用者的所有角色
    ctx := context.Background()
    roles, err := a.rbacSvc.GetUserRolesMe(ctx, userID, model.GetUserRolesMeReq{})

    // 3. 建構 NATS UserClaims
    uc := jwt.NewUserClaims(req.UserNkey)
    uc.Audience = "$G" // 或指定的 Account public key
    uc.Expires = time.Now().Add(1 * time.Hour).Unix()

    // 4. 設定 NATS Pub/Sub 權限（粗粒度）
    natsPerms := MapRolesToNATSPermissions(roles)
    uc.Pub = natsPerms.Pub
    uc.Sub = natsPerms.Sub

    // 5. 簽署並回傳 JWT
    return uc.Encode(a.accountKP)
}
```

#### [NEW] [permissions_map.go](file:///c:/Users/wenmo/work/rbac7/internal/rbac/nats/permissions_map.go)

RBAC 角色 → NATS subject 權限映射：

```go
// NATSPermissions 封裝 publish/subscribe 允許清單
type NATSPermissions struct {
    Pub jwt.Permission
    Sub jwt.Permission
}

func MapRolesToNATSPermissions(roles []*model.UserRole) NATSPermissions {
    perms := NATSPermissions{}
    
    // 所有已認證使用者都可以存取權限檢查 subject
    perms.Pub.Allow.Add("rbac.permissions.check")
    perms.Pub.Allow.Add("rbac.permissions.check.batch")
    perms.Sub.Allow.Add("_INBOX.>") // 接收 reply

    for _, role := range roles {
        if role.Scope == model.ScopeSystem {
            ns := strings.ToLower(role.Namespace)
            switch role.Role {
            case "moderator", "owner", "admin":
                // 完整管理權限
                perms.Pub.Allow.Add(fmt.Sprintf("rbac.system.%s.>", ns))
            case "dev_user":
                // 資源操作但不含成員管理
                perms.Pub.Allow.Add(fmt.Sprintf("rbac.system.%s.resource.>", ns))
            case "viewer":
                // 唯讀
                perms.Pub.Allow.Add(fmt.Sprintf("rbac.system.%s.read", ns))
            }
        }
        // resource scope 角色依類似邏輯映射
    }
    return perms
}
```

> [!NOTE]
> 這裡採用的是「粗粒度」映射 — 限制使用者能存取的 subject 範圍，但不取代 RBAC policy engine 的細粒度檢查。細粒度權限仍由 Phase 3 的 NATS handler 中呼叫 service 層進行。

---

### Phase 3: NATS Request-Reply Handlers

#### [NEW] [handler.go](file:///c:/Users/wenmo/work/rbac7/internal/rbac/nats/handler.go)

NATS handler 層，模式與 HTTP handler 完全對稱：

```go
// NATSHandler 處理 NATS request-reply 訊息
type NATSHandler struct {
    svc  service.RBACService
    conn *nats.Conn
    subs []*nats.Subscription
}

// NATSRequest 統一的 NATS 訊息格式
type NATSRequest struct {
    CallerID string          `json:"caller_id"`
    Data     json.RawMessage `json:"data"`
}

// NATSResponse 統一的 NATS 回應格式
type NATSResponse struct {
    Success bool        `json:"success"`
    Data    interface{} `json:"data,omitempty"`
    Error   *NATSError  `json:"error,omitempty"`
}

type NATSError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}
```

Subject 對照表：

| NATS Subject | 對應 Service 方法 | 需要 RBAC 檢查 |
|---|---|---|
| `rbac.permissions.check` | [CheckPermission](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#33-34) | ❌ (任何人) |
| `rbac.permissions.check.batch` | [BatchCheckPermission](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#132-156) | ❌ (任何人) |
| `rbac.system.assign_owner` | [AssignSystemOwner](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#21-22) | ✅ |
| `rbac.system.transfer_owner` | [TransferSystemOwner](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#22-23) | ✅ |
| `rbac.system.assign_role` | [AssignSystemUserRole](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#23-24) | ✅ |
| `rbac.system.assign_roles_batch` | [AssignSystemUserRoles](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#24-25) | ✅ |
| `rbac.system.delete_role` | [DeleteSystemUserRole](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#24-26) | ✅ |
| `rbac.system.get_my_roles` | [GetUserRolesMe](file:///c:/Users/wenmo/work/rbac7/internal/rbac/handler/handler_common.go#27-54) | ✅ (self_roles) |
| `rbac.system.get_members` | [GetUserRoles](file:///c:/Users/wenmo/work/rbac7/internal/rbac/handler/handler_common.go#55-80) | ✅ |
| `rbac.system.get_logs` | [GetUserRoleHistory](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#207-223) | ✅ |
| `rbac.resource.assign_owner` | [AssignResourceOwner](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#28-29) | ✅ |
| `rbac.resource.transfer_owner` | [TransferResourceOwner](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#29-30) | ✅ |
| `rbac.resource.assign_role` | [AssignResourceUserRole](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#30-31) | ✅ |
| `rbac.resource.assign_roles_batch` | [AssignResourceUserRoles](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#31-32) | ✅ |
| `rbac.resource.delete_role` | [DeleteResourceUserRole](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#31-33) | ✅ |
| `rbac.resource.delete` | [SoftDeleteResource](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#35-37) | ✅ |
| `rbac.resource.get_dashboard` | [GetDashboardResource](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#37-38) | ✅ |

每個 handler 的流程：

```
NATS Message (subject + reply)
  │
  ▼
1. JSON 反序列化 → NATSRequest { caller_id, data }
  │
  ▼
2. 從 data 反序列化具體 request DTO (e.g., AssignSystemOwnerReq)
  │
  ▼
3. 呼叫 req.Validate()
  │
  ▼
4. [需 RBAC 的 subject] 呼叫 PolicyEngine.CheckOperationPermission()
  │
  ▼
5. 呼叫 Service 方法
  │
  ▼
6. 序列化 NATSResponse → 發送到 reply subject
```

#### [NEW] [middleware.go](file:///c:/Users/wenmo/work/rbac7/internal/rbac/nats/middleware.go)

NATS 層的 RBAC 中間件（對應 HTTP 的 [rbac_middleware.go](file:///c:/Users/wenmo/work/rbac7/internal/rbac/handler/rbac_middleware.go)）：

```go
// NATSRBACMiddleware 在 NATS handler 層執行 RBAC 權限檢查
type NATSRBACMiddleware struct {
    policyEngine *policy.Engine
    repo         repository.RBACRepository
}

// CheckPermission 在執行 handler 前檢查權限
func (m *NATSRBACMiddleware) CheckPermission(
    ctx context.Context, callerID string, 
    entity, operation string, params map[string]string,
) (bool, error) {
    // 建構 OperationRequest 並呼叫 PolicyEngine
    opReq := policy.OperationRequest{
        CallerID:  callerID,
        Entity:    entity,
        Operation: operation,
        // ... 從 params 填入 namespace, resource_id 等
    }
    return m.policyEngine.CheckOperationPermission(ctx, m.repo, &opReq)
}
```

---

### Phase 4: main.go 整合

#### [MODIFY] [main.go](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go)

新增 NATS 啟動邏輯（同時保留 HTTP）：

```go
func main() {
    // ... 現有 HTTP 啟動邏輯 ...

    // NATS 啟動（條件式）
    if cfg.NATSEnabled {
        // 1. 連線到 NATS
        nc, err := nats.Connect(cfg.NATSURL,
            nats.UserInfo(cfg.NATSAuthUser, cfg.NATSAuthPassword),
            nats.MaxReconnects(-1),
        )

        // 2. 啟動 Auth Callout Service
        authCallout, err := natshandler.NewAuthCalloutService(nc, svc, cfg)

        // 3. 註冊 NATS Request-Reply Handlers
        natsHandler := natshandler.NewNATSHandler(nc, svc, svc.Policy, repo)
        natsHandler.RegisterAll()

        // 4. Graceful Shutdown 加入 NATS 清理
        defer nc.Close()
        defer authCallout.Stop()
        defer natsHandler.UnsubscribeAll()
    }
}
```

---

### 新增依賴

#### [MODIFY] [go.mod](file:///c:/Users/wenmo/work/rbac7/go.mod)

```
require (
    // 現有依賴 ...
    github.com/nats-io/nats.go        v1.x.x
    github.com/nats-io/jwt/v2         v2.x.x
    github.com/nats-io/nkeys          v0.x.x
    github.com/synadia-io/callout.go  v0.2.x
)
```

---

### 新增專案結構總覽

```
internal/rbac/nats/         # 【新增目錄】
├── auth_callout.go         # Auth Callout 服務 (使用 callout.go 函式庫)
├── permissions_map.go      # RBAC 角色 → NATS subject 權限映射
├── handler.go              # NATS request-reply handlers (對應 HTTP handlers)
├── middleware.go            # NATS 層 RBAC 權限檢查
├── error.go                # NATS 錯誤處理 (對應 HTTP error.go)
└── handler_test.go         # NATS handler 單元測試
```

---

## Verification Plan

### Automated Tests

1. **`permissions_map.go` 單元測試**
   ```bash
   cd c:\Users\wenmo\work\rbac7
   go test ./internal/rbac/nats/... -run TestMapRolesToNATSPermissions -v
   ```
   - 測試各角色組合產生正確的 NATS subject 權限
   - 測試空角色、多角色、system + resource 混合情境

2. **NATS Handler 單元測試**（使用 mock service，與現有 HTTP 測試對稱）
   ```bash
   cd c:\Users\wenmo\work\rbac7
   go test ./internal/rbac/nats/... -run TestNATSHandler -v
   ```
   - 驗證 JSON 序列化/反序列化
   - 驗證錯誤碼映射
   - 驗證 RBAC 檢查在 NATS handler 層正確執行

3. **確認現有測試未被破壞**
   ```bash
   cd c:\Users\wenmo\work\rbac7
   go test ./tests/... -v
   ```

### Manual Verification

> [!IMPORTANT]
> 整合測試需要一個運行中的 NATS Server (v2.10+) 和 MongoDB。以下步驟需要你在本機環境中手動執行。

1. **啟動 NATS Server** 並設定 auth callout config
2. **啟動 RBAC Service** 設定 `NATS_ENABLED=true` 等環境變數
3. **用 NATS CLI 測試連線**：確認 Auth Callout 能正確處理連線
4. **用 NATS CLI 發送 request**：測試 `rbac.permissions.check` 等 subject

> 由於整合測試環境複雜，建議先完成單元測試，再由你手動測試整合環境。具體 NATS server 設定和測試步驟需要你確認環境後再細化。
