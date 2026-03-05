# RBAC System 完整架構規格文件

> 本文件詳細描述 RBAC (Role-Based Access Control) 系統的完整架構、資料模型、API 設計、權限引擎、業務邏輯和實作細節，目標是讓 AI 能根據此文件重新生成相同功能的系統。

---

## 1. 系統概述

### 1.1 技術棧

| 項目 | 技術 |
|------|------|
| 語言 | Go 1.24.6 |
| HTTP 框架 | Echo v4.14.0 |
| 資料庫 | MongoDB (mongo-driver v1.17.6) |
| 驗證 | go-playground/validator/v10 |
| 測試 | testify v1.11.1 |

### 1.2 專案結構

```
rbac7/
├── cmd/server/main.go          # 應用程式入口
├── docs/
│   ├── rbac.yaml               # OpenAPI 3.0.3 規格
│   └── seed_org_system_roles.json
├── internal/rbac/
│   ├── config/config.go        # 環境變數設定
│   ├── handler/                # HTTP Handler 層
│   │   ├── handler_common.go   # 共用 API (GetUserRoles, CheckPermission)
│   │   ├── handler_system.go   # System scope API
│   │   ├── handler_resource.go # Resource scope API
│   │   ├── rbac_middleware.go  # 策略驅動的權限中間件
│   │   ├── middleware.go       # RequestID 中間件
│   │   └── error.go           # 錯誤處理映射
│   ├── model/                  # 資料模型 + Request DTO + 驗證
│   │   ├── types.go            # 核心類型 (UserRole, SystemUserRole, etc.)
│   │   ├── constants.go        # 角色/權限/Scope 常數
│   │   ├── validator.go        # 驗證器單例
│   │   ├── user_role_history.go
│   │   ├── batch_upsert_result.go
│   │   └── *_req.go            # 各 API 請求驗證 (共 14 個)
│   ├── policy/                 # 策略引擎 (核心)
│   │   ├── engine.go           # 權限檢查引擎
│   │   ├── loader.go           # 策略載入器 (embed.FS)
│   │   ├── types.go            # 策略類型定義
│   │   └── policies/           # 嵌入式 JSON 策略檔
│   │       ├── operations/     # 實體操作策略 (4 個 JSON)
│   │       ├── roles/          # 角色權限映射 (2 個 JSON)
│   │       └── check_permission.json
│   ├── repository/             # 資料存取層
│   │   ├── repository.go       # RBACRepository 介面
│   │   ├── history_repository.go
│   │   ├── org_user_repository.go
│   │   ├── mongo_common_impl.go
│   │   ├── mongo_system_impl.go
│   │   └── mongo_resource_impl.go
│   ├── router/router.go        # 路由註冊
│   ├── service/                # 業務邏輯層
│   │   ├── service_common.go   # RBACService 介面 + 共用邏輯
│   │   ├── service_system.go   # System scope 業務
│   │   └── service_resource.go # Resource scope 業務
│   └── util/logger.go
└── tests/                      # 整合測試 (22 個檔案)
```

---

## 2. 核心概念模型

### 2.1 雙 Scope 架構

系統分為兩大 Scope，**各自使用獨立的 MongoDB Collection**：

| Scope | Collection | 說明 |
|-------|-----------|------|
| `system` | `user_roles` | 平台級角色 (與 namespace 綁定) |
| `resource` | `user_resource_roles` | 資源級角色 (與 resource_id + resource_type 綁定) |

### 2.2 角色階層

#### System Roles (高 → 低)

| 角色 | 優先序 | 說明 |
|------|--------|------|
| `moderator` | 6 | 超級管理員，僅能指派 owner |
| `owner` | 5 | 命名空間擁有者，可管理成員 |
| `admin` | 4 | 管理員，權限同 owner 但不能轉移 |
| `dev_user` | 2 | 開發者，可操作資源但不能管成員 |
| `viewer` | 1 | 只讀 |

> **可指派角色** (透過 API assign)：`admin`, `dev_user`, `viewer` (owner 只能透過 assign_owner/transfer_owner)

#### Resource Roles (高 → 低)

| 角色 | 優先序 | 說明 |
|------|--------|------|
| `owner` | 5 | 資源擁有者 |
| `admin` | 4 | 管理員 |
| `editor` | 3 | 編輯者 |
| `viewer` | 1 | 只讀 |

### 2.3 使用者類型 (user_type)

| 類型 | 說明 |
|------|------|
| `member` | 一般使用者 (預設) |
| `org` | 組織單位 (用於 Org 權限繼承) |

### 2.4 資源類型 (resource_type)

| 類型 | 說明 | 父資源 |
|------|------|--------|
| `dashboard` | 儀表板 | 無 |
| `dashboard_widget` | 儀表板的子 Widget | `dashboard` |
| `library_widget` | 共用元件庫 Widget | 無 (透過 namespace 管理) |

---

## 3. 資料模型

### 3.1 UserRole (核心模型)

```go
type UserRole struct {
    ID               string     `bson:"_id,omitempty"`
    UserID           string     `bson:"user_id"`
    UserType         string     `bson:"user_type"`          // "member" | "org"
    Role             string     `bson:"role"`
    Scope            string     `bson:"scope"`              // "system" | "resource"
    Namespace        string     `bson:"namespace,omitempty"`
    ResourceID       string     `bson:"resource_id,omitempty"`
    ResourceType     string     `bson:"resource_type,omitempty"`
    ParentResourceID string     `bson:"parent_resource_id,omitempty"`
    // 審計欄位
    CreatedAt        time.Time  `bson:"created_at"`
    UpdatedAt        time.Time  `bson:"updated_at"`
    DeletedAt        *time.Time `bson:"deleted_at,omitempty"` // 軟刪除
    CreatedBy        string     `bson:"created_by,omitempty"`
    UpdatedBy        string     `bson:"updated_by,omitempty"`
    DeletedBy        string     `bson:"deleted_by,omitempty"`
}
```

### 3.2 UserRoleHistory (審計日誌 - append-only)

```go
type UserRoleHistory struct {
    ID               string    `bson:"_id,omitempty"`
    Operation        string    `bson:"operation"`   // 操作類型
    CallerID         string    `bson:"caller_id"`
    Scope            string    `bson:"scope"`
    Namespace        string    `bson:"namespace,omitempty"`
    ResourceID       string    `bson:"resource_id,omitempty"`
    ResourceType     string    `bson:"resource_type,omitempty"`
    ParentResourceID string    `bson:"parent_resource_id,omitempty"`
    UserID           string    `bson:"user_id,omitempty"`    // 單一操作
    UserIDs          []string  `bson:"user_ids,omitempty"`   // 批次操作
    UserType         string    `bson:"user_type,omitempty"`
    Role             string    `bson:"role,omitempty"`
    NewOwnerID       string    `bson:"new_owner_id,omitempty"`
    ChildResourceIDs []string  `bson:"child_resource_ids,omitempty"`
    CreatedAt        time.Time `bson:"created_at"`
}
```

**Operation 類型**: `assign_owner`, `transfer_owner`, `assign_user_role`, `assign_user_roles_batch`, `delete_user_role`, `delete_resource`

### 3.3 OrgUser (組織使用者資料)

```go
type OrgUser struct {
    UserID      string `bson:"user_id"`
    FunctionID  string `bson:"function_id"`
    FunctionID1 string `bson:"function_id1,omitempty"`
    DivisionID  string `bson:"division_id"`
    DeptID      string `bson:"dept_id"`
    SectID      string `bson:"sect_id"`
}
```

> [OrgIDs()](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/org_user_repository.go#22-42) 方法回傳所有非空欄位值組成的 slice，用於查詢 user_type=org 的角色。

### 3.4 MongoDB 索引設計

#### user_roles Collection
1. **唯一索引** `uniq_user_per_namespace_scope`: [(user_id, user_type, scope, namespace)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129) UNIQUE
2. **部分唯一索引** `unique_system_owner_v2`: [(scope, namespace)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129) UNIQUE WHERE `scope=system AND role=owner AND deleted_at=nil`

#### user_resource_roles Collection
1. **唯一索引** `uniq_user_per_resource_scope`: [(user_id, user_type, scope, resource_type, resource_id)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129) UNIQUE
2. **部分唯一索引** `unique_resource_owner`: [(scope, resource_id, resource_type)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129) UNIQUE WHERE `scope=resource AND role=owner AND deleted_at=nil`

#### user_role_history Collection
1. `idx_system_scope_query`: [(scope, namespace, created_at DESC)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129)
2. `idx_resource_scope_query`: [(scope, resource_id, resource_type, created_at DESC)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129)
3. `idx_created_at`: [(created_at DESC)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129)

---

## 4. 策略引擎 (Policy Engine)

### 4.1 設計理念

權限檢查透過 **嵌入式 JSON 策略檔** 驅動，而非硬編碼，實現宣告式權限管理。策略檔在編譯時嵌入二進位檔 (`embed.FS`)。

### 4.2 CheckScope 類型

| CheckScope | 說明 | 參數需求 |
|------------|------|----------|
| `none` | 不需權限檢查 | 無 |
| `system` | 檢查 System 角色 | namespace |
| `resource` | 檢查 Resource 角色 | resource_id, resource_type |
| `parent_resource` | 檢查父資源角色 | parent_resource_id |
| `self_roles` | 檢查自身角色是否有權限 | 透過已載入的 roles 判斷 |
| `global` | 檢查全域角色 (不限 namespace) | 無 |

### 4.3 角色-權限映射

#### System Roles ([system_roles.json](file:///c:/Users/wenmo/work/rbac7/docs/seed_org_system_roles.json))

```json
{
    "moderator": [
        "platform.system.create",
        "platform.system.read",
        "platform.system.add_owner"
    ],
    "owner": [
        "platform.system.update", "platform.system.read",
        "platform.system.add_member", "platform.system.remove_member",
        "platform.system.get_member", "platform.system.transfer_owner",
        "platform.system.read_log",
        "system.resource.create", "system.resource.read",
        "system.resource.delete", "system.resource.update",
        "system.resource.publish",
        "resource.library_widget.get_member"
    ],
    "admin": [
        "platform.system.update", "platform.system.read",
        "platform.system.add_member", "platform.system.remove_member",
        "platform.system.get_member", "platform.system.read_log",
        "system.resource.create", "system.resource.read",
        "system.resource.delete", "system.resource.update",
        "system.resource.publish",
        "resource.library_widget.get_member"
    ],
    "dev_user": [
        "platform.system.read",
        "system.resource.create", "system.resource.read",
        "system.resource.delete", "system.resource.update",
        "system.resource.publish"
    ],
    "viewer": [
        "platform.system.read",
        "system.resource.read"
    ]
}
```

#### Resource Roles ([resource_roles.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/roles/resource_roles.json))

```json
{
    "owner": [
        "resource.dashboard.read", "resource.dashboard.update",
        "resource.dashboard.delete", "resource.dashboard.add_member",
        "resource.dashboard.remove_member", "resource.dashboard.get_member",
        "resource.dashboard.transfer_owner",
        "resource.dashboard.add_widget", "resource.dashboard.remove_widget",
        "resource.dashboard.add_widget_viewer", "resource.dashboard.read_log",
        "resource.dashboard_widget.read", "resource.dashboard_widget.get_member",
        "resource.library_widget.read"
    ],
    "admin": [
        "resource.dashboard.read", "resource.dashboard.update",
        "resource.dashboard.delete", "resource.dashboard.add_member",
        "resource.dashboard.remove_member", "resource.dashboard.get_member",
        "resource.dashboard.add_widget", "resource.dashboard.remove_widget",
        "resource.dashboard.add_widget_viewer", "resource.dashboard.read_log",
        "resource.dashboard_widget.read", "resource.dashboard_widget.get_member",
        "resource.library_widget.read"
    ],
    "editor": [
        "resource.dashboard.read", "resource.dashboard.update",
        "resource.dashboard.add_widget", "resource.dashboard.remove_widget",
        "resource.dashboard.add_widget_viewer",
        "resource.dashboard_widget.read", "resource.dashboard_widget.get_member"
    ],
    "viewer": [
        "resource.dashboard.read",
        "resource.dashboard_widget.read",
        "resource.library_widget.read"
    ]
}
```

### 4.4 實體操作策略

每個實體有獨立的 JSON 設定檔，定義所有操作的權限需求和 API 路由映射。

#### System Entity ([system.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/operations/system.json))

| 操作 | 權限 | CheckScope | API |
|------|------|------------|-----|
| `assign_owner` | `platform.system.add_owner` | `global` | POST /user_roles/owner |
| `transfer_owner` | `platform.system.transfer_owner` | `system` (namespace_required) | PUT /user_roles/owner |
| `assign_user_role` | `platform.system.add_member` | `system` (namespace_required) | POST /user_roles |
| `assign_user_roles_batch` | `platform.system.add_member` | `system` (namespace_required) | POST /user_roles/batch |
| `delete_user_role` | `platform.system.remove_member` | `system` (namespace_required) | DELETE /user_roles |
| `get_members` | `platform.system.get_member` | `system` (namespace_required) | GET /user_roles (condition: scope=system) |
| `get_my_roles` | `platform.system.read` | `self_roles` | GET /user_roles/me (condition: scope=system) |
| `read_log` | `platform.system.read_log` | `system` (namespace_required) | GET /user_roles/logs (condition: scope=system) |

#### Dashboard Entity ([dashboard.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/operations/dashboard.json))

| 操作 | 權限 | CheckScope | API |
|------|------|------------|-----|
| `assign_owner` | (無) | `none` | POST /user_roles/resources/owner (condition: resource_type=dashboard) |
| `transfer_owner` | `resource.dashboard.transfer_owner` | `resource` | PUT /user_roles/resources/owner |
| `assign_user_role` | `resource.dashboard.add_member` | `resource` | POST /user_roles/resources |
| `assign_user_roles_batch` | `resource.dashboard.add_member` | `resource` | POST /user_roles/resources/batch |
| `delete_user_role` | `resource.dashboard.remove_member` | `resource` | DELETE /user_roles/resources |
| `get_members` | `resource.dashboard.get_member` | `resource` | GET /user_roles (condition: scope=resource, resource_type=dashboard) |
| `get_my_roles` | `resource.dashboard.read` | `self_roles` | GET /user_roles/me |
| `delete_resource` | `resource.dashboard.delete` | `resource` | PUT /resources/delete |
| `get_dashboard` | `resource.dashboard.read` | `resource` | POST /resources/dashboards |
| `read_log` | `resource.dashboard.read_log` | `resource` | GET /user_roles/logs |

#### Dashboard Widget Entity ([dashboard_widget.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/operations/dashboard_widget.json))

> `parent_entity: "dashboard"` — 所有操作都檢查**父 dashboard** 的權限

| 操作 | 權限 | CheckScope |
|------|------|------------|
| `assign_viewer` | `resource.dashboard.add_widget_viewer` | `parent_resource` |
| `assign_user_roles_batch` | `resource.dashboard.add_widget_viewer` | `parent_resource` |
| `delete_viewer` | `resource.dashboard.add_widget_viewer` | `parent_resource` |
| `get_members` | `resource.dashboard_widget.get_member` | `parent_resource` |
| `delete_resource` | `resource.dashboard.delete` | `parent_resource` |
| `read_log` | `resource.dashboard.read_log` | `parent_resource` |

**特殊邏輯**: 當 `resource_type=dashboard_widget` 且 `role=viewer` 時，Engine 自動將 `assign_user_role` → `assign_viewer`，`delete_user_role` → `delete_viewer`。

#### Library Widget Entity ([library_widget.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/operations/library_widget.json))

| 操作 | 權限 | CheckScope |
|------|------|------------|
| `assign_viewer` | `platform.system.add_member` | `system` (namespace_required) |
| `assign_viewers_batch` | `platform.system.add_member` | `system` (namespace_required) |
| `delete_viewer` | `platform.system.remove_member` | `system` (namespace_required) |
| `get_members` | `resource.library_widget.get_member` | `system` (namespace_required) |
| `get_my_roles` | `resource.library_widget.read` | `self_roles` |
| `delete_resource` | `system.resource.delete` | `system` (namespace_required) |
| `read_log` | `platform.system.read_log` | `system` (namespace_required) |

### 4.5 CheckPermission API 繼承策略 ([check_permission.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/check_permission.json))

```json
{
    "resource_types": {
        "dashboard": { "inheritance": "none" },
        "dashboard_widget": {
            "inheritance": "parent_if_no_roles",
            "parent_type": "dashboard",
            "permission_mapping": {
                "resource.dashboard_widget.read": "resource.dashboard.read"
            }
        },
        "library_widget": { "inheritance": "public_if_no_roles" }
    }
}
```

| 繼承模式 | 行為 |
|----------|------|
| `none` | 直接檢查該資源的角色 |
| `parent_if_no_roles` | 若資源無角色 → 繼承父資源權限；若有角色 → 嚴格白名單檢查 |
| `public_if_no_roles` | 若資源無角色 → 公開存取 (任何人可讀)；若有角色 → 嚴格白名單檢查 |

---

## 5. RBAC Middleware (策略驅動)

### 5.1 運作流程

```
HTTP Request
    │
    ▼
1. 建構 lookup key: "METHOD:PATH" (例：POST:/api/v1/user_roles)
    │
    ▼
2. 查找匹配的 APIConfig (可能有多個 config 對應同一 path)
    │
    ▼
3. 提取 callerID (x-user-id header，必填)
    │
    ▼
4. 解析 request body (POST/PUT/DELETE)
    │
    ▼
5. 用 condition 匹配正確的 config
   (例：同一 path 但 resource_type=dashboard vs dashboard_widget)
    │
    ▼
6. 驗證必填參數 (namespace_required, resource_id_required, parent_resource_required)
    │
    ▼
7. 建構 OperationRequest 並呼叫 PolicyEngine.CheckOperationPermission()
    │
    ▼
8. allowed=true → 繼續；allowed=false → 403 Forbidden
```

### 5.2 參數提取

策略 JSON 中的 `params` 定義參數來源：
- `body.namespace` → 從 request body JSON 提取
- `query.resource_id` → 從 URL query string 提取
- `path.id` → 從 URL path 參數提取
- `header.x-namespace` → 從 HTTP header 提取

### 5.3 Condition 匹配

當同一 API path 有多個實體策略時，透過 condition 區分：

```json
// dashboard 的 assign_user_role
{ "condition": { "resource_type": "dashboard" } }

// dashboard_widget 的 assign_viewer
{ "condition": { "resource_type": "dashboard_widget", "role": "viewer" } }
```

---

## 6. API 端點規格

### 6.1 路由配置

```
Base URL: /api/v1

# 無 RBAC Middleware 保護 (任何人可呼叫)
POST   /permissions/check           # 單一權限檢查
POST   /permissions/check/batch     # 批次權限檢查

# 受 RBAC Middleware 保護
# System Scope
POST   /user_roles/owner            # 指派系統 Owner
PUT    /user_roles/owner            # 轉移系統 Owner
POST   /user_roles                  # 指派系統角色
POST   /user_roles/batch            # 批次指派系統角色
DELETE /user_roles                  # 刪除系統角色
GET    /user_roles/me               # 取得自身角色
GET    /user_roles                  # 取得成員列表
GET    /user_roles/logs             # 取得角色變更日誌

# Resource Scope
POST   /user_roles/resources/owner  # 指派資源 Owner
PUT    /user_roles/resources/owner  # 轉移資源 Owner
POST   /user_roles/resources        # 指派資源角色
POST   /user_roles/resources/batch  # 批次指派資源角色
DELETE /user_roles/resources        # 刪除資源角色

# Resource Management
PUT    /resources/delete            # 軟刪除資源
POST   /resources/dashboards       # 取得 Dashboard 資源

# 其他
GET    /health
GET    /docs/rbac.yaml
```

### 6.2 認證方式

- `x-user-id` header：必填，識別呼叫者
- `authentication` header：認證 token (目前 RBAC 系統本身不驗證，由上層 Gateway 處理)

---

## 7. 核心業務邏輯

### 7.1 Owner 保護機制

- **無法透過 assign_user_role 指派 owner**：必須使用 assign_owner / transfer_owner
- **Upsert 時保護 owner**：MongoDB filter 加上 `role: {$ne: "owner"}` 防止覆蓋
- **唯一 owner 不可降級**：當 namespace/resource 只剩一個 owner 時，禁止刪除或變更該 owner 的角色
- **轉移使用 Transaction**：降級舊 owner 為 admin + 升級新 owner 原子操作

### 7.2 Dashboard Widget 存取控制

**繼承模式** (widget 無任何角色)：
- Widget 繼承父 Dashboard 的權限 → 有 dashboard read 權限就能看

**白名單模式** (widget 有角色被指派)：
- 嚴格檢查 widget 本身的角色 → 只有被明確加入的使用者才能看

**指派 Widget Viewer 的前置條件**：
- 目標使用者必須先有父 Dashboard 的 read 權限

### 7.3 Cascade 刪除

**刪除 Dashboard 成員時**：
- 自動清除該使用者在所有子 Widget 的白名單角色 ([DeleteUserRolesByParent](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/repository.go#44-46))

**軟刪除 Dashboard 資源時**：
- 可傳入 `child_resource_ids` 一次刪除 dashboard + 所有子 widget 的角色

### 7.4 Org 權限繼承

系統支援「組織權限」概念，流程如下：

```
1. 使用者的個人角色檢查 (member 類型)
   └─ 若有權限 → 允許 (結束)
2. 查詢 org_users collection 取得使用者的組織屬性
   └─ 取得 orgIDs: [function_id, function_id1, division_id, dept_id, sect_id]
3. 查詢 user_roles 中 user_type=org 且 user_id IN orgIDs 的所有角色
4. 取最高優先序的角色 (GetMaxRole)
5. 檢查該角色是否有所需權限
```

> Org 權限只在 [CheckPermission](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#33-34) 和 [BatchCheckPermission](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#34-35) API 中生效，不影響 RBAC Middleware。

### 7.5 軟刪除 (Soft Delete)

所有刪除操作都是軟刪除：
- 設定 `deleted_at` 時間戳和 `deleted_by`
- 查詢時 filter `deleted_at: nil`
- Upsert 時清除已軟刪除的記錄 (`$unset: {deleted_at: "", deleted_by: ""}`)

### 7.6 History 記錄

所有寫入操作都會非同步記錄到 `user_role_history` collection：
- 使用 goroutine fire-and-forget 方式 (5 秒 timeout)
- History 是 append-only，建立後不可修改

---

## 8. Repository 介面

### 8.1 RBACRepository (18 個方法)

```go
type RBACRepository interface {
    GetSystemOwner(ctx, namespace) (*UserRole, error)
    CreateUserRole(ctx, role) error
    HasSystemRole(ctx, userID, namespace, role) (bool, error)
    HasAnySystemRole(ctx, userID, namespace, roles[]) (bool, error)
    FindUserRoles(ctx, filter) ([]*UserRole, error)
    EnsureIndexes(ctx) error
    TransferSystemOwner(ctx, namespace, oldOwnerID, newOwnerID, updatedBy) error
    UpsertUserRole(ctx, role) error
    DeleteUserRole(ctx, namespace, userID, scope, resourceID, resourceType, parentResourceID, deletedBy) error
    CountSystemOwners(ctx, namespace) (int64, error)
    CountResourceOwners(ctx, resourceID, resourceType) (int64, error)
    HasResourceRole(ctx, userID, resourceID, resourceType, role) (bool, error)
    HasAnyResourceRole(ctx, userID, resourceID, resourceType, roles[]) (bool, error)
    TransferResourceOwner(ctx, resourceID, resourceType, oldOwnerID, newOwnerID, updatedBy) error
    CountResourceRoles(ctx, resourceID, resourceType) (int64, error)
    BulkUpsertUserRoles(ctx, roles[]) (*BatchUpsertResult, error)
    DeleteUserRolesByParent(ctx, userID, parentResourceID, resourceType, deletedBy) error
    SoftDeleteResourceUserRoles(ctx, req, deletedBy) error
    FindUserRolesByUserIDs(ctx, userIDs[], userType, scope, namespace, resourceID, resourceType) ([]*UserRole, error)
}
```

### 8.2 HistoryRepository

```go
type HistoryRepository interface {
    CreateHistory(ctx, history) error
    FindHistory(ctx, req) ([]*UserRoleHistory, total int64, error)
    EnsureHistoryIndexes(ctx) error
}
```

### 8.3 OrgUserRepository

```go
type OrgUserRepository interface {
    GetOrgUser(ctx, userID) (*OrgUser, error)
}
```

> [MongoRepository](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/mongo_common_impl.go#14-20) 同時實作 [RBACRepository](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/repository.go#11-51) 和 [HistoryRepository](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/history_repository.go#10-18) 兩個介面。

### 8.4 Collection 路由邏輯

Repository 根據 scope 路由到不同 collection：
- `scope=system` → `SystemRoles` collection
- `scope=resource` → [ResourceRoles](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/mongo_resource_impl.go#138-147) collection
- [FindUserRoles](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/mongo_common_impl.go#334-411) 若 scope 為空 → 查詢兩個 collection 合併結果

---

## 9. 設定管理

### 環境變數

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB 連接字串 |
| `PORT` | `8080` | 服務埠 |
| `DB_NAME` | `rbac_db` | 資料庫名 |
| `COLLECTION_USER_ROLES` | `user_roles` | System scope collection |
| `COLLECTION_RESOURCE_ROLES` | `user_resource_roles` | Resource scope collection |
| `COLLECTION_ORG_USERS` | `org_users` | Org user data collection |
| `SERVER_READ_TIMEOUT` | `10s` | HTTP 讀取超時 |
| `SERVER_WRITE_TIMEOUT` | `10s` | HTTP 寫入超時 |

---

## 10. Request 驗證規則

每個 Request DTO 都有 [Validate()](file:///c:/Users/wenmo/work/rbac7/internal/rbac/model/check_permission_req.go#14-36) 方法，包含：
1. **字串正規化**：`TrimSpace`、`ToUpper`(namespace)、`ToLower`(scope, resource_type)
2. **結構驗證**：使用 `go-playground/validator` (required, min, max, oneof 標籤)
3. **業務驗證**：條件性必填欄位檢查

### 關鍵驗證邏輯：

| Request | 特殊驗證 |
|---------|----------|
| `AssignSystemUserRoleReq` | `role` 必須為 `oneof=admin viewer dev_user moderator` |
| `AssignResourceUserRoleReq` | 若 `resource_type=dashboard_widget` 則 `parent_resource_id` 必填 |
| `AssignResourceUserRolesReq` | `user_ids` 最多 50 個，不可重複不可為空 |
| `DeleteResourceUserRoleReq` | 若 `resource_type=dashboard_widget` 則 `parent_resource_id` 必填 |
| `SoftDeleteResourceReq` | 若 `resource_type=dashboard_widget` 則 `parent_resource_id` 必填；若 `library_widget` 則 `namespace` 必填 |
| [CheckPermissionReq](file:///c:/Users/wenmo/work/rbac7/internal/rbac/model/check_permission_req.go#5-13) | 若 `scope=resource` 則 `resource_id` + `resource_type` 必填 |
| `GetUserRoleHistoryReq` | `page` 和 `size` 有預設值，支援時間範圍過濾 |

---

## 11. 錯誤處理

### HTTP 錯誤碼映射

| Service Error | HTTP Status | Error Code |
|--------------|-------------|------------|
| `ErrUnauthorized` | 401 | `unauthorized` |
| `ErrForbidden` | 403 | `forbidden` |
| `ErrConflict` | 409 | `conflict` |
| `ErrBadRequest` / `ErrInvalidNamespace` | 400 | `bad_request` |
| 其他錯誤 | 500 | `internal_error` |

### 錯誤回應格式

```json
{
    "error": {
        "code": "forbidden",
        "message": "Permission denied",
        "request_id": "req_123456"
    }
}
```

---

## 12. 啟動流程 (main.go)

```
1. InitLogger()
2. LoadConfig() → 載入環境變數
3. mongo.Connect() → 連接 MongoDB
4. NewMongoRepository() → 初始化 RBACRepository
5. NewMongoOrgUserRepository() → 初始化 OrgUserRepository
6. EnsureIndexes() → 確保索引 (非致命失敗)
7. EnsureHistoryIndexes()
8. NewServiceWithOrg() → 初始化 Service (含 PolicyEngine)
9. NewSystemHandler() → 初始化 Handler
10. LoadAPIConfigs() → 從策略建構 API 路由映射
11. RegisterRoutes() → 註冊所有路由和中間件
12. ListenAndServe() + Graceful Shutdown (SIGINT/SIGTERM)
```

---

## 13. 測試架構

22 個整合測試檔案，使用 mock repository，涵蓋：

| 測試檔案 | 涵蓋功能 |
|----------|----------|
| [rbac_middleware_test.go](file:///c:/Users/wenmo/work/rbac7/tests/rbac_middleware_test.go) | RBAC 中間件端對端測試 |
| [post_permissions_check_test.go](file:///c:/Users/wenmo/work/rbac7/tests/post_permissions_check_test.go) | 權限檢查 (member) |
| [post_permissions_check_org_test.go](file:///c:/Users/wenmo/work/rbac7/tests/post_permissions_check_org_test.go) | 權限檢查 (org 繼承) |
| [post_permissions_check_batch_test.go](file:///c:/Users/wenmo/work/rbac7/tests/post_permissions_check_batch_test.go) | 批次權限檢查 |
| [dashboard_widget_test.go](file:///c:/Users/wenmo/work/rbac7/tests/dashboard_widget_test.go) | Widget 存取控制 |
| [get_dashboard_resource_test.go](file:///c:/Users/wenmo/work/rbac7/tests/get_dashboard_resource_test.go) | Dashboard 資源 API |
| [post_resource_user_roles_batch_test.go](file:///c:/Users/wenmo/work/rbac7/tests/post_resource_user_roles_batch_test.go) | 批次資源角色指派 |
| 各 CRUD 測試 | Owner/Role 指派、轉移、刪除 |

---

## 14. 關鍵設計決策總結

1. **雙 Collection 架構**：System 和 Resource 角色分開存儲，避免相互干擾
2. **策略驅動權限**：JSON 策略檔宣告式定義，中間件自動執行，新增實體無需改寫程式碼
3. **軟刪除**：保留歷史紀錄，支援資料恢復
4. **Org 權限 fallback**：先查個人角色 → 再通過組織屬性繼承角色
5. **Widget 雙模式存取**：繼承模式 (免設定) vs 白名單模式 (精確控制)
6. **Owner 保護**：多重機制防止意外失去唯一 Owner
7. **History fire-and-forget**：非同步記錄不影響 API 效能
8. **Namespace 大寫正規化**：所有 namespace 都轉大寫確保一致性
