# Space ABAC 授權流程範例（中文）

## 狀態

討論版流程附錄，可搭配設計文件使用。

## 日期

2026-03-31

## 參考文件

- [Space Authorization Design (ABAC + OPA, Option B)](/C:/Users/wenmo/work/rbac7/docs/plans/2026-03-29-space-abac-authz-design.md)
- [Space Authorization Design (ABAC + OPA, Option B, 中文)](/C:/Users/wenmo/work/rbac7/docs/plans/2026-03-29-space-abac-authz-design-zh.md)

## 說明

本文件將先前討論的 8 個 end-to-end 流程整理成可直接溝通與實作的參考格式。

這些流程遵循同一套責任邊界：

- `FE` 只呼叫 `Space BE` / `Resource BE`
- `Space BE` 管 canonical policy、members、groups、org bindings
- `Auth Platform` 管 projections 與 OPA decision
- `Resource BE` 管 resource 主資料與 hard enforcement

## Projection 與資料責任

### 核心結論

- `OPA` 不負責持久化資料
- `Auth Platform` 負責存放 runtime projection
- `Space BE` 負責存放 human-editable 的 canonical policy 與 members/groups/org 主資料

可以把責任拆成三層：

1. `Space BE`
   - 存管理者編輯的原始資料
   - 例如 permission matrix、channel override、members、groups、org-role mapping
2. `Auth Platform`
   - 存給 OPA decision 使用的 projection
   - 例如 `space_principal_bindings`、`space_policy_manifests`、`space_policy_rule_sets`
3. `OPA`
   - 不持久化 projection
   - 只消費 `Auth Platform` 在 runtime 提供的 subject/resource/action/rule data

### `rule_set` 要存在哪裡

`rule_set` 應該存放在 `Auth Platform`，不是存放在 `OPA`，也不是把 `Space BE` 當成 runtime rule source。

責任如下：

- `Space BE`：在 publish 時 compile 出 `rule_set`
- `Auth Platform`：持久化 `rule_set`，作為 decision hot path 的 runtime policy store
- `OPA`：在 decision 時讀取 `rule_set`，做 allow/deny 判斷

一句話：

- `rule_set` 由 `Space BE` 產生，存進 `Auth Platform`，再由 `OPA` 執行

### 資料責任對照表

| 物件 | 實體存放位置 | Source of Truth | 誰建立 | 建立時機 | 用途 |
|---|---|---|---|---|---|
| `space_principal_bindings` | `Auth Platform` DB | `Space BE` | `Space BE` 產生 payload，`Auth Platform` 寫入 | member / org-role / group membership 變更時 | 把 `user/org` 映射成 `space` 內的 `role/group` 身份 |
| `space_policy_manifests` | `Auth Platform` DB | runtime state 在 `Auth Platform`，來源 metadata 由 `Space BE` 提供 | `Auth Platform` 建立或更新 | policy upload / activate 時 | 記錄 active `policy_version`、checksum、published_at、status |
| `space_policy_rule_sets` | `Auth Platform` DB | `Space BE` 編譯結果 | `Space BE` 產生 payload，`Auth Platform` 寫入 | permissions publish / override publish 時 | 提供 `OPA` decision 使用的 grouped rule data |
| `space_policy_projection` | 建議不要單獨落一張表；概念上等於 `manifest + rule_sets` | 邏輯概念，不是獨立 SoT | `Space BE` compile 時形成 projection payload | policy publish 時 | 表示一整包可供 runtime decision 的 compiled policy |

### `space_policy_projection` 是否要獨立存成一張表

設計上不建議把 `space_policy_projection` 做成一張獨立 collection / table。

比較好的做法是拆成兩部分：

- `space_policy_manifests`
  - 管版本、checksum、active pointer
- `space_policy_rule_sets`
  - 管每個 `(space_id, policy_version, resource_type, action)` 的規則內容

所以：

- `space_policy_projection` 是概念上的總稱
- `manifest + rule_sets` 才是實際 runtime 落地結構

### 每個 projection 回答的問題

#### `space_principal_bindings`

回答的是：

- 誰在這個 `space` 裡，會變成什麼身份

例子：

- `org:backend_engineering -> role:member`
- `user:u_alice -> role:owner`
- `user:u_bob -> group:devops`

它不是 policy。
它不回答 `member` 能做什麼。
它只回答誰是 `member`、誰在 `devops`。

#### `space_policy_rule_sets`

回答的是：

- 這些身份可以做什麼

例子：

- `space.view`
- `document.create`
- `channel.post_message`
- `channel.pin_message`

它是給 `OPA` 跑的 compiled policy data。

#### `space_policy_manifests`

回答的是：

- 這個 `space` 目前到底哪一個 `policy_version` 正在生效

例子：

- `engineering -> active_policy_version = 17`

它不是規則內容本身，而是 active policy pointer 與 metadata。

#### `space_policy_projection`

它是總稱，表示：

- 一份從 canonical policy compile 出來，可供 `Auth Platform` 直接做 decision 的 runtime projection

但實際落地時，建議拆成：

- `manifest`
- `rule_sets`

### 建立時機與 data flow

#### A. member / org / group 變更

1. `owner` 在 UI 改 members / org-role / group
2. `FE -> Space BE`
3. `Space BE` 更新主資料
4. `Space BE -> Auth Platform: PUT /v2/internal/spaces/{space_id}/bindings/batch`
5. `Auth Platform` 更新 `space_principal_bindings`

這條流程通常不碰 policy。

#### B. permissions / override 變更

1. `owner` 在 UI 改 permissions / channel override
2. `FE -> Space BE`
3. `Space BE` 更新 canonical policy
4. `Space BE` compile 出 `space_policy_projection`
5. `Space BE -> Auth Platform: PUT /v2/internal/spaces/{space_id}/policies/{policy_version}/rule-sets`
6. `Space BE -> Auth Platform: POST /v2/internal/spaces/{space_id}/policies/{policy_version}/activate`
7. `Auth Platform` 更新 `space_policy_rule_sets + space_policy_manifests`

這條流程才會更新 compiled policy。

#### C. user 進行 runtime decision

1. user 帶 token 進來
2. `Auth Platform` 驗 token
3. 讀 `org_user_snapshots`
4. 讀 `space_principal_bindings`
5. 組出 effective subject
6. 讀 `space_policy_manifests` 找 active version
7. 讀 `space_policy_rule_sets`
8. 丟給 `OPA` 做 decision

所以 `OPA` runtime 真正依賴的是：

- `org_user_snapshots`
- `space_principal_bindings`
- `space_policy_manifests`
- `space_policy_rule_sets`

### 最容易對齊團隊的版本

#### 放在 `Space BE`

- canonical permission matrix
- channel overrides
- members
- groups master data
- org-role assignments 的原始管理資料

#### 放在 `Auth Platform`

- `org_user_snapshots`
- `space_principal_bindings`
- `space_policy_manifests`
- `space_policy_rule_sets`

#### 放在 `OPA`

- 不持久化以上資料
- 只做 evaluate

## `Space BE` 與 `Resource BE` 的 rule ownership

### 核心結論

這不是二選一，而是分兩層：

- `Space BE` 定義 `space-scoped` 的授權規則
- `Resource BE` 定義 resource 的授權語意、action catalog、resource attrs，並做最後 enforcement

所以真正要分清楚的是：

- 誰定義授權模型契約
- 誰編輯 `space` 的 policy
- 誰提供 runtime resource 狀態
- 誰執行 hard enforcement

### 具體責任切分

| 題目 | 責任方 | 說明 |
|---|---|---|
| 這個 resource 有哪些 action 可授權，例如 `read/update/delete/post_message` | `Resource BE` | resource domain 自己定義 action catalog |
| 這些 action 要不要出現在 `Space Management > Permissions / Channels` 這種統一管理 UI 裡 | `Space BE` | `Space BE` 決定是否納入 `space` 統一 policy |
| 哪些 `role/group/org` 對這些 action 是 `allow/deny/inherit` | `Space BE` | `Space BE` 是 policy authoring layer |
| 某筆 resource 目前的 `owner_id/classification/visibility/...` 是什麼 | `Resource BE` | resource metadata source of truth 在 `Resource BE` |
| 真正執行操作前要不要放行 | `Resource BE` + `Auth Platform` | `Auth Platform` 判斷，`Resource BE` enforce |

### 用白話講

`Space BE` 不是去擁有 resource domain。

`Space BE` 擁有的是：

- 哪些 resource type 被納入 `space` 的統一授權
- 這些 resource type 的 `role/group/org` 規則
- 哪些 channel 或 resource instance 需要 override

`Resource BE` 擁有的是：

- 這個 resource type 到底有哪些 action
- 這個 resource decision 時要帶哪些 attrs
- 這筆 resource 實際現在長什麼樣
- 寫操作前最後要不要放行

### 例子一：`document`

#### `Resource BE` 定義

- actions: `read/create/update/delete`
- attrs: `owner_id`, `classification`, `visibility`

#### `Space BE` 定義

- `Member` 可不可以 `document.read`
- `Admin` 可不可以 `document.delete`
- `reviewers` 可不可以讀 `classification=restricted`

#### `Resource BE` runtime

- 讀出 `doc_123` 的 `classification=restricted`
- 問 `Auth Platform`
- 決定是否回資料或 `403`

### 例子二：`channel`

#### `Resource BE` 或 channel service 定義

- actions: `join/post_message/pin_message/manage_settings`
- attrs: `resource_id`, `visibility`

#### `Space BE` 定義

- 基礎 matrix
- `#incidents` 的 override

#### `Resource BE` runtime

- 判斷 `general` 或 `incidents`
- 帶入 `resource_id`
- 問 `Auth Platform`

### 推薦落地方式

每個 `Resource BE` 對 `Space BE` 提供一份 `authorization contract`。

例如：

```json
{
  "resource_type": "document",
  "actions": ["read", "create", "update", "delete"],
  "supported_attrs": ["owner_id", "classification", "visibility"],
  "supports_instance_override": true
}
```

然後：

- `Space BE` 用這份 contract 決定 UI 上能配置哪些權限
- `Space BE` compile 成 `space_policy_rule_sets`
- `Resource BE` 在 runtime 提供 attrs 並做 hard enforcement

### 一句話總結

`Space BE` 應該定義「`space` 裡這些 resource 的授權規則」，
但 `Resource BE` 應該定義「這些 resource 有哪些 action、有哪些屬性、以及實際 resource 狀態」。

兩邊是合作，不是二選一。

## 共用情境

### 共用角色

- `moderator`: `u_mod_001`
- `owner`: `u_alice`
- `member-by-org user`: `u_bob`
- `space_id`: `engineering`
- `org_id`: `backend_engineering`
- `group_id`: `devops`

### 共用預設規則

- `Owner`: 可管理整個 `space`
- `Member`:
  - `space.view = true`
  - `dashboard.read = true`
  - `document.create = true`
  - `channel.join = true`
  - `channel.post_message = true`
  - `space.manage_members = false`
  - `space.manage_permissions = false`
  - `audit_log.view = false`
- `general` channel 沒有 override，沿用基礎規則
- `incidents` channel 有 override: `devops` group 可以 `pin_message`

---

## 流程一：`moderator` 定義某個 `space` 的 default policy rule

### 流程目的

- `moderator` 在 UI 上編輯 canonical policy
- `Space BE` compile 出 compiled policy
- `Space BE` 呼叫 `Auth Platform` 上傳與 activate policy version

### Step 1. FE 讀取目前 `space` 的權限設定

**Request**

```http
GET /api/spaces/engineering/permissions/config
Authorization: Bearer <moderator-token>
```

**Response**

```json
{
  "space_id": "engineering",
  "matrix_version": 1,
  "roles": ["owner", "admin", "member", "guest"],
  "permissions": [
    {
      "resource_type": "space",
      "action": "view",
      "cells": {
        "owner": "allow",
        "admin": "allow",
        "member": "allow",
        "guest": "inherit"
      }
    },
    {
      "resource_type": "channel",
      "action": "post_message",
      "cells": {
        "owner": "allow",
        "admin": "allow",
        "member": "allow",
        "guest": "deny"
      }
    }
  ],
  "resource_overrides": []
}
```

### Step 2. FE 儲存 canonical policy

**Request**

```http
PUT /api/spaces/engineering/permissions/config
Authorization: Bearer <moderator-token>
Content-Type: application/json
```

```json
{
  "matrix_version": 2,
  "roles": ["owner", "admin", "member", "guest"],
  "permissions": [
    {
      "resource_type": "space",
      "action": "view",
      "cells": {
        "owner": "allow",
        "admin": "allow",
        "member": "allow",
        "guest": "deny"
      }
    },
    {
      "resource_type": "dashboard",
      "action": "read",
      "cells": {
        "owner": "allow",
        "admin": "allow",
        "member": "allow",
        "guest": "deny"
      }
    },
    {
      "resource_type": "channel",
      "action": "post_message",
      "cells": {
        "owner": "allow",
        "admin": "allow",
        "member": "allow",
        "guest": "deny"
      }
    }
  ],
  "resource_overrides": []
}
```

**Response**

```json
{
  "space_id": "engineering",
  "matrix_version": 2,
  "status": "saved_draft"
}
```

### Step 3. FE 發布 policy

**Request**

```http
POST /api/spaces/engineering/permissions/publish
Authorization: Bearer <moderator-token>
Content-Type: application/json
```

```json
{
  "matrix_version": 2,
  "reason": "initialize default policy for engineering space"
}
```

**Response**

```json
{
  "space_id": "engineering",
  "policy_version": 1,
  "status": "publishing"
}
```

### Step 4. `Space BE` 呼叫 `Auth Platform` 上傳 compiled rule sets

**Internal Request**

```http
PUT /v2/internal/spaces/engineering/policies/1/rule-sets
Authorization: Bearer <space-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "policy_version": 1,
  "source_matrix_version": 2,
  "compiler_version": "space-policy-compiler/v1",
  "checksum": "sha256:policy-v1",
  "published_by": {
    "actor_type": "user",
    "actor_id": "u_mod_001"
  },
  "rule_sets": [
    {
      "resource_type": "space",
      "action": "view",
      "default_effect": "deny",
      "rules": [
        {
          "rule_id": "role-matrix-space-view-member",
          "source_kind": "role_matrix",
          "effect": "allow",
          "priority": 750,
          "target_scope": "type",
          "target_resource_id": null,
          "principal_any": ["space:engineering:role:member"],
          "subject_conditions": [],
          "resource_conditions": [],
          "env_conditions": [],
          "enabled": true
        }
      ]
    },
    {
      "resource_type": "channel",
      "action": "post_message",
      "default_effect": "deny",
      "rules": [
        {
          "rule_id": "role-matrix-channel-post-message-member",
          "source_kind": "role_matrix",
          "effect": "allow",
          "priority": 750,
          "target_scope": "type",
          "target_resource_id": null,
          "principal_any": ["space:engineering:role:member"],
          "subject_conditions": [],
          "resource_conditions": [],
          "env_conditions": [],
          "enabled": true
        }
      ]
    }
  ]
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "policy_version": 1,
  "status": "draft_uploaded",
  "received_rule_set_count": 2,
  "stored_rule_set_count": 2
}
```

### Step 5. `Space BE` activate policy

**Internal Request**

```http
POST /v2/internal/spaces/engineering/policies/1/activate
Authorization: Bearer <space-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "policy_version": 1,
  "expected_checksum": "sha256:policy-v1",
  "expected_rule_set_count": 2,
  "activated_by": {
    "actor_type": "user",
    "actor_id": "u_mod_001"
  },
  "reason": "publish default policy"
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "active_policy_version": 1,
  "previous_policy_version": null,
  "status": "active"
}
```

---

## 流程二：`moderator` 把某個人加進來當 `space owner`

### 流程目的

- policy 已經定義 `owner` 能做什麼
- 本流程要做的是讓 `u_alice` 成為 `owner`

### Step 1. FE 新增 owner

**Request**

```http
POST /api/spaces/engineering/members/users
Authorization: Bearer <moderator-token>
Content-Type: application/json
```

```json
{
  "user_id": "u_alice",
  "role": "owner"
}
```

**Response**

```json
{
  "space_id": "engineering",
  "user_id": "u_alice",
  "role": "owner",
  "status": "saved"
}
```

### Step 2. `Space BE` 更新 `Auth Platform` bindings

**Internal Request**

```http
PUT /v2/internal/spaces/engineering/bindings/batch
Authorization: Bearer <space-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "binding_version": 1,
  "source_updated_at": "2026-03-31T09:00:00Z",
  "sync_mode": "delta",
  "upserts": [
    {
      "principal_type": "user",
      "principal_id": "u_alice",
      "grant_tokens": [
        "space:engineering:role:owner"
      ]
    }
  ],
  "deletes": []
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "binding_version": 1,
  "status": "applied",
  "applied": {
    "upserts": 1,
    "deletes": 0
  }
}
```

---

## 流程三：owner login 進來後，UI 如何呈現

### 流程目的

- `owner` 登入後，`FE` 透過 capability snapshot 決定頁籤、按鈕與管理入口

### Step 1. FE 取得 `space` 級 capability

**Request**

```http
GET /api/spaces/engineering/me/capabilities
Authorization: Bearer <owner-token>
```

**Response**

```json
{
  "space_id": "engineering",
  "policy_version": 1,
  "capabilities": {
    "space.view": true,
    "space.manage_members": true,
    "space.manage_groups": true,
    "space.manage_permissions": true,
    "audit_log.view": true,
    "document.create": true,
    "channel.create": true
  }
}
```

**UI 呈現**

- 顯示 `Members / Roles / Permissions / Channels / Audit Log`
- 顯示 `Invite Member`
- 顯示 `Create Channel`
- 顯示 `Copy Settings / Export Report`

### Step 2. FE 取得頁面級 resource type capability

**Request**

```http
POST /api/spaces/engineering/me/resource-type-capabilities
Authorization: Bearer <owner-token>
Content-Type: application/json
```

```json
{
  "resource_types": ["dashboard", "document", "channel", "file", "task"],
  "actions": ["create", "read", "update", "delete", "manage_permissions"]
}
```

**Response**

```json
{
  "space_id": "engineering",
  "capabilities": {
    "dashboard": {
      "read": true,
      "update": true,
      "delete": true
    },
    "document": {
      "create": true,
      "read": true,
      "update": true,
      "delete": true,
      "manage_permissions": true
    },
    "channel": {
      "create": true,
      "read": true,
      "update": true,
      "delete": true,
      "manage_permissions": true
    }
  }
}
```

### Step 3. `Space BE -> Auth Platform` internal decision

**Internal Request**

```http
POST /v2/internal/decisions/check/batch
Authorization: Bearer <space-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "requests": [
    {
      "resource": {
        "resource_id": "engineering",
        "resource_type": "space",
        "space_id": "engineering"
      },
      "actions": ["view", "manage_members", "manage_groups", "manage_permissions"]
    },
    {
      "resource": {
        "resource_id": "dashboard-type",
        "resource_type": "dashboard",
        "space_id": "engineering"
      },
      "actions": ["create", "read", "update", "delete"]
    }
  ]
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "policy_version": 1,
  "results": [
    {
      "resource_id": "engineering",
      "decisions": {
        "view": { "allow": true },
        "manage_members": { "allow": true },
        "manage_groups": { "allow": true },
        "manage_permissions": { "allow": true }
      }
    }
  ]
}
```

---

## 流程四：owner 想要修改 rule

### 流程目的

- `owner` 修改 canonical policy
- `Space BE` compile 出新的 compiled policy version
- 透過 upload + activate 讓新版本生效

### 例子

- `owner` 把 `member` 的 `document.create` 從 `allow` 改成 `deny`

### Step 1. FE 讀取目前設定

**Request**

```http
GET /api/spaces/engineering/permissions/config
Authorization: Bearer <owner-token>
```

### Step 2. FE 儲存修改後的 canonical policy

**Request**

```http
PUT /api/spaces/engineering/permissions/config
Authorization: Bearer <owner-token>
Content-Type: application/json
```

```json
{
  "matrix_version": 3,
  "permissions": [
    {
      "resource_type": "document",
      "action": "create",
      "cells": {
        "owner": "allow",
        "admin": "allow",
        "member": "deny",
        "guest": "deny"
      }
    }
  ]
}
```

**Response**

```json
{
  "space_id": "engineering",
  "matrix_version": 3,
  "status": "saved_draft"
}
```

### Step 3. FE 發布

**Request**

```http
POST /api/spaces/engineering/permissions/publish
Authorization: Bearer <owner-token>
Content-Type: application/json
```

```json
{
  "matrix_version": 3,
  "reason": "member should no longer create documents"
}
```

**Response**

```json
{
  "space_id": "engineering",
  "policy_version": 2,
  "status": "publishing"
}
```

### Step 4. `Space BE` 上傳新 rule set

**Internal Request**

```http
PUT /v2/internal/spaces/engineering/policies/2/rule-sets
Authorization: Bearer <space-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "policy_version": 2,
  "source_matrix_version": 3,
  "checksum": "sha256:policy-v2",
  "rule_sets": [
    {
      "resource_type": "document",
      "action": "create",
      "default_effect": "deny",
      "rules": [
        {
          "rule_id": "role-matrix-document-create-owner",
          "effect": "allow",
          "priority": 750,
          "target_scope": "type",
          "principal_any": ["space:engineering:role:owner"],
          "enabled": true
        },
        {
          "rule_id": "role-matrix-document-create-admin",
          "effect": "allow",
          "priority": 750,
          "target_scope": "type",
          "principal_any": ["space:engineering:role:admin"],
          "enabled": true
        },
        {
          "rule_id": "role-matrix-document-create-member",
          "effect": "deny",
          "priority": 800,
          "target_scope": "type",
          "principal_any": ["space:engineering:role:member"],
          "enabled": true
        }
      ]
    }
  ]
}
```

### Step 5. activate 新 version

**Internal Request**

```http
POST /v2/internal/spaces/engineering/policies/2/activate
Authorization: Bearer <space-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "policy_version": 2,
  "expected_checksum": "sha256:policy-v2",
  "expected_rule_set_count": 1,
  "activated_by": {
    "actor_type": "user",
    "actor_id": "u_alice"
  }
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "active_policy_version": 2,
  "previous_policy_version": 1,
  "status": "active"
}
```

---

## 流程五：owner 想要加 org 到某個 role，想要加 group

### 流程目的

- `org -> role` 屬於 binding
- `user -> group` 也屬於 binding
- 如果 group 還要有特殊權限，才需要另外更新 policy

### 5A. owner 把 org 加到 `member` role

**Request**

```http
POST /api/spaces/engineering/members/orgs
Authorization: Bearer <owner-token>
Content-Type: application/json
```

```json
{
  "org_id": "backend_engineering",
  "role": "member"
}
```

**Response**

```json
{
  "space_id": "engineering",
  "org_id": "backend_engineering",
  "role": "member",
  "status": "saved"
}
```

**Internal Request**

```http
PUT /v2/internal/spaces/engineering/bindings/batch
Authorization: Bearer <space-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "binding_version": 2,
  "sync_mode": "delta",
  "upserts": [
    {
      "principal_type": "org",
      "principal_id": "backend_engineering",
      "grant_tokens": [
        "space:engineering:role:member"
      ]
    }
  ],
  "deletes": []
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "binding_version": 2,
  "status": "applied"
}
```

### 5B. owner 建立 group

**Request**

```http
POST /api/spaces/engineering/groups
Authorization: Bearer <owner-token>
Content-Type: application/json
```

```json
{
  "group_id": "devops",
  "name": "DevOps",
  "description": "DevOps on-call team"
}
```

**Response**

```json
{
  "space_id": "engineering",
  "group_id": "devops",
  "status": "created"
}
```

### 5C. owner 把 Bob 加進 `devops` group

**Request**

```http
POST /api/spaces/engineering/groups/devops/members
Authorization: Bearer <owner-token>
Content-Type: application/json
```

```json
{
  "user_id": "u_bob"
}
```

**Response**

```json
{
  "space_id": "engineering",
  "group_id": "devops",
  "user_id": "u_bob",
  "status": "added"
}
```

**Internal Request**

```http
PUT /v2/internal/spaces/engineering/bindings/batch
Authorization: Bearer <space-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "binding_version": 3,
  "sync_mode": "delta",
  "upserts": [
    {
      "principal_type": "user",
      "principal_id": "u_bob",
      "grant_tokens": [
        "space:engineering:group:devops"
      ]
    }
  ],
  "deletes": []
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "binding_version": 3,
  "status": "applied"
}
```

### 5D. 如果 owner 還要讓 `devops` 在 `incidents` 有特殊權限

這一步才需要改 policy。

**Request**

```http
PUT /api/spaces/engineering/channels/incidents/overrides
Authorization: Bearer <owner-token>
Content-Type: application/json
```

```json
{
  "action": "pin_message",
  "group_id": "devops",
  "effect": "allow"
}
```

之後會重走流程四的 `publish -> PUT rule-sets -> activate`

---

## 流程六：某個 user 他的 org 的 role 是 `member`，他登進來後 UI 如何呈現

### 流程目的

- `u_bob` 因為 `backend_engineering -> member` binding，自動成為 `member`
- UI 依 capability snapshot 呈現一般成員可以看到的頁面與按鈕

### Step 1. FE 取得 `space` 級 capability

**Request**

```http
GET /api/spaces/engineering/me/capabilities
Authorization: Bearer <bob-token>
```

**Response**

```json
{
  "space_id": "engineering",
  "policy_version": 2,
  "capabilities": {
    "space.view": true,
    "space.manage_members": false,
    "space.manage_groups": false,
    "space.manage_permissions": false,
    "audit_log.view": false,
    "document.create": false,
    "channel.create": false
  }
}
```

`document.create = false`，因為流程四中 owner 已改掉該規則。

**UI 呈現**

- 顯示 `Home / Documents / Files / Tasks / Channels`
- 隱藏 `Members / Permissions / Audit Log`
- 不顯示 `Create Document`
- 不顯示 `Create Channel`

### Step 2. FE 取得頁面級 capability

**Request**

```http
POST /api/spaces/engineering/me/resource-type-capabilities
Authorization: Bearer <bob-token>
Content-Type: application/json
```

```json
{
  "resource_types": ["dashboard", "document", "channel"],
  "actions": ["read", "create", "update", "delete", "manage_settings", "post_message"]
}
```

**Response**

```json
{
  "space_id": "engineering",
  "capabilities": {
    "dashboard": {
      "read": true,
      "update": false
    },
    "document": {
      "read": true,
      "create": false,
      "update": false,
      "delete": false
    },
    "channel": {
      "read": true,
      "post_message": true,
      "manage_settings": false
    }
  }
}
```

---

## 流程七：某個 user 他的 org 的 role 是 `member`，他操作 dashboard 裡面的 `DevOps Monitor`

### 流程目的

- `u_bob` 可以看 `DevOps Monitor`
- 但不能編輯這個 dashboard

### Step 1. FE 載入 dashboard 列表

**Request**

```http
GET /api/spaces/engineering/dashboards
Authorization: Bearer <bob-token>
```

### Step 2. `Resource BE` 查 dashboard 資料後，問 `Auth Platform` instance capability

**Internal Request**

```http
POST /v2/internal/decisions/check/batch
Authorization: Bearer <resource-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "requests": [
    {
      "resource": {
        "resource_id": "devops-monitor",
        "resource_type": "dashboard",
        "space_id": "engineering",
        "owner_id": "u_alice",
        "visibility": "space"
      },
      "actions": ["read", "update", "delete"]
    }
  ]
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "policy_version": 2,
  "results": [
    {
      "resource_id": "devops-monitor",
      "decisions": {
        "read": { "allow": true, "matched_rule_id": "role-matrix-dashboard-read-member" },
        "update": { "allow": false, "matched_rule_id": "", "reason": "default deny" },
        "delete": { "allow": false, "matched_rule_id": "", "reason": "default deny" }
      }
    }
  ]
}
```

### Step 3. `Resource BE` 回 FE 列表資料 + capability

**Response**

```json
{
  "items": [
    {
      "dashboard_id": "devops-monitor",
      "name": "DevOps Monitor",
      "capabilities": {
        "read": true,
        "update": false,
        "delete": false
      }
    }
  ]
}
```

**UI 呈現**

- 可以看到 `DevOps Monitor` 卡片
- 可以點進去看
- 不顯示 `Edit Dashboard`

### Step 4. Bob 點進 `DevOps Monitor`

**Request**

```http
GET /api/spaces/engineering/dashboards/devops-monitor
Authorization: Bearer <bob-token>
```

`Resource BE` 會再做一次 hard check。

**Internal Request**

```http
POST /v2/internal/decisions/check
Authorization: Bearer <resource-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "action": "read",
  "resource": {
    "resource_id": "devops-monitor",
    "resource_type": "dashboard",
    "space_id": "engineering",
    "visibility": "space"
  }
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "policy_version": 2,
  "decision": {
    "allow": true,
    "matched_rule_id": "role-matrix-dashboard-read-member"
  }
}
```

**Response**

```json
{
  "dashboard_id": "devops-monitor",
  "title": "DevOps Monitor",
  "widgets": [
    { "widget_id": "uptime", "type": "metric" },
    { "widget_id": "incidents", "type": "list" }
  ]
}
```

### Step 5. 如果 Bob 想編輯 dashboard

**Request**

```http
PATCH /api/spaces/engineering/dashboards/devops-monitor
Authorization: Bearer <bob-token>
Content-Type: application/json
```

```json
{
  "title": "DevOps Monitor v2"
}
```

**Internal Response from Auth**

```json
{
  "space_id": "engineering",
  "decision": {
    "allow": false,
    "reason": "default deny"
  }
}
```

**Final Response**

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "You do not have permission to update this dashboard"
  }
}
```

---

## 流程八：某個 user 他的 org 的 role 是 `member`，他操作 channel 裡面的 `general`

### 流程目的

- `general` 沒有 override
- 所以 `general` 完全走 base matrix
- `member` 的 `channel.post_message = true`

### Step 1. FE 載入 channel 列表

**Request**

```http
GET /api/spaces/engineering/channels
Authorization: Bearer <bob-token>
```

### Step 2. `Resource BE` 問 instance capability

**Internal Request**

```http
POST /v2/internal/decisions/check/batch
Authorization: Bearer <resource-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "requests": [
    {
      "resource": {
        "resource_id": "general",
        "resource_type": "channel",
        "space_id": "engineering",
        "visibility": "space"
      },
      "actions": ["join", "post_message", "pin_message", "manage_settings"]
    }
  ]
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "policy_version": 2,
  "results": [
    {
      "resource_id": "general",
      "decisions": {
        "join": {
          "allow": true,
          "matched_rule_id": "role-matrix-channel-join-member"
        },
        "post_message": {
          "allow": true,
          "matched_rule_id": "role-matrix-channel-post-message-member"
        },
        "pin_message": {
          "allow": false,
          "reason": "default deny"
        },
        "manage_settings": {
          "allow": false,
          "reason": "default deny"
        }
      }
    }
  ]
}
```

### Step 3. `Resource BE` 回 FE channel 列表 + capability

**Response**

```json
{
  "items": [
    {
      "channel_id": "general",
      "name": "general",
      "capabilities": {
        "join": true,
        "post_message": true,
        "pin_message": false,
        "manage_settings": false
      }
    }
  ]
}
```

**UI 呈現**

- 可以進 `general`
- 可以看到輸入框
- 不顯示 `Pin Message`
- 不顯示 `Manage Channel Settings`

### Step 4. Bob 在 `general` 發訊息

**Request**

```http
POST /api/spaces/engineering/channels/general/messages
Authorization: Bearer <bob-token>
Content-Type: application/json
```

```json
{
  "content": "Staging deployment is complete."
}
```

`Resource BE` 寫入前先做 hard check。

**Internal Request**

```http
POST /v2/internal/decisions/check
Authorization: Bearer <resource-be-service-token>
Content-Type: application/json
```

```json
{
  "space_id": "engineering",
  "action": "post_message",
  "resource": {
    "resource_id": "general",
    "resource_type": "channel",
    "space_id": "engineering",
    "visibility": "space"
  }
}
```

**Internal Response**

```json
{
  "space_id": "engineering",
  "policy_version": 2,
  "decision": {
    "allow": true,
    "matched_rule_id": "role-matrix-channel-post-message-member"
  }
}
```

**Final Response**

```json
{
  "message_id": "msg_1001",
  "channel_id": "general",
  "status": "posted"
}
```

### Step 5. 如果 Bob 想 pin 訊息

**Request**

```http
POST /api/spaces/engineering/channels/general/messages/msg_1001/pin
Authorization: Bearer <bob-token>
```

**Internal Response from Auth**

```json
{
  "space_id": "engineering",
  "decision": {
    "allow": false,
    "reason": "default deny"
  }
}
```

**Final Response**

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "You do not have permission to pin messages in this channel"
  }
}
```

---

## 總結

## 總流程對照表

| 流程 | 使用者動作 | FE API | Space/Resource BE API | Auth Platform Internal API | OPA 判斷點 | UI 結果 |
|---|---|---|---|---|---|---|
| 1 | `moderator` 定義 `space` default policy | `GET /api/spaces/{space_id}/permissions/config`<br>`PUT /api/spaces/{space_id}/permissions/config`<br>`POST /api/spaces/{space_id}/permissions/publish` | `Space BE` 儲存 canonical policy、compile rule sets、產生 `policy_version` | `PUT /v2/internal/spaces/{space_id}/policies/{policy_version}/rule-sets`<br>`POST /v2/internal/spaces/{space_id}/policies/{policy_version}/activate` | 無 runtime OPA decision；此流程是 policy authoring 與 projection publish | `Permissions` 頁顯示新規則，發布成功後後續使用者進入 space 會吃到新版本 |
| 2 | `moderator` 把某人加成 `owner` | `POST /api/spaces/{space_id}/members/users` | `Space BE` 更新 member 主資料、產生新 `binding_version` | `PUT /v2/internal/spaces/{space_id}/bindings/batch` | 無 runtime OPA decision；此流程是 principal binding projection | 該使用者下次進入 `space` 時會被視為 `owner` |
| 3 | `owner` login 進入 `space` | `GET /api/spaces/{space_id}/me/capabilities`<br>`POST /api/spaces/{space_id}/me/resource-type-capabilities` | `Space BE` 組裝 space/page capability snapshot | `POST /v2/internal/decisions/check/batch` | `Auth Platform` 驗 token、讀 `org_user_snapshot`、讀 `space_principal_bindings`、載入 `space` 與 page-level `rule_sets`，OPA 判斷 owner 的 space/page actions | 顯示 `Members / Permissions / Channels / Audit Log`，顯示管理按鈕與建立資源入口 |
| 4 | `owner` 修改 rule 並發布 | `GET /api/spaces/{space_id}/permissions/config`<br>`PUT /api/spaces/{space_id}/permissions/config`<br>`POST /api/spaces/{space_id}/permissions/publish` | `Space BE` 更新 canonical policy、compile 新版 rule sets、產生新 `policy_version` | `PUT /v2/internal/spaces/{space_id}/policies/{policy_version}/rule-sets`<br>`POST /v2/internal/spaces/{space_id}/policies/{policy_version}/activate` | 無 runtime OPA decision；此流程是重新發布 compiled policy | `Permissions` 頁看到新規則，後續 capability 與 hard enforcement 會切到新版本 |
| 5 | `owner` 把某個 org 加到 role、建立 group、把 user 加入 group | `POST /api/spaces/{space_id}/members/orgs`<br>`POST /api/spaces/{space_id}/groups`<br>`POST /api/spaces/{space_id}/groups/{group_id}/members`<br>若 group 有特殊權限再 `PUT /api/spaces/{space_id}/channels/{channel_id}/overrides` 或更新 permissions | `Space BE` 更新 org/member/group 主資料；若有特殊權限再 compile 新 policy | `PUT /v2/internal/spaces/{space_id}/bindings/batch`<br>若改權限則再 `PUT .../rule-sets` + `POST .../activate` | 無 runtime OPA decision；此流程主要更新 bindings，若有特殊權限才更新 policy | 指定 org 進 space 後自動取得 role；group 成員之後會吃到 group-based capability |
| 6 | org role 為 `member` 的 user 登入 | `GET /api/spaces/{space_id}/me/capabilities`<br>`POST /api/spaces/{space_id}/me/resource-type-capabilities` | `Space BE` 對 FE 回 space/page capability snapshot | `POST /v2/internal/decisions/check/batch` | `Auth Platform` 由 user token 找到 org，再由 `org -> role:member` binding 推得 `member`，OPA 判斷 space/page actions | 顯示一般成員頁面，例如 `Home / Documents / Files / Tasks / Channels`；隱藏 `Members / Permissions / Audit Log` |
| 7 | org role 為 `member` 的 user 操作 dashboard `DevOps Monitor` | `GET /api/spaces/{space_id}/dashboards`<br>`GET /api/spaces/{space_id}/dashboards/{dashboard_id}`<br>若要編輯則 `PATCH /api/spaces/{space_id}/dashboards/{dashboard_id}` | `Resource BE` 查 dashboard candidate set、回列表資料與 instance capability，寫操作前做 hard enforcement | `POST /v2/internal/decisions/check/batch`<br>`POST /v2/internal/decisions/check` | `Auth Platform` 載入 `dashboard.read/update/delete` 的 `rule_sets`；OPA 依 user 的 effective `member` 身份判斷可讀不可改 | 可看到 `DevOps Monitor` 並點進查看；不顯示或無法成功執行 `Edit Dashboard` |
| 8 | org role 為 `member` 的 user 操作 channel `general` | `GET /api/spaces/{space_id}/channels`<br>`POST /api/spaces/{space_id}/channels/{channel_id}/messages`<br>若要 pin 則 `POST /api/spaces/{space_id}/channels/{channel_id}/messages/{message_id}/pin` | `Resource BE` 查 channel 列表、回 instance capability，發文或 pin 前做 hard enforcement | `POST /v2/internal/decisions/check/batch`<br>`POST /v2/internal/decisions/check` | `Auth Platform` 載入 `channel.join/post_message/pin_message/manage_settings` 的 `rule_sets`；OPA 對 `general` 套用 base matrix，因無 override 所以直接走 type-level rules | 可進 `general`、可發文；不可 pin message、不可管理 channel 設定 |

這 8 個流程都圍繞同一個核心原則：

1. `Space BE` 管 canonical policy 與 group/member/org 主資料
2. `Auth Platform` 管 projections 與 OPA decision
3. `Resource BE` 在真正操作 resource 前做 hard enforcement

可以用下面三句快速記住整體設計：

- `bindings` 決定「誰在這個 space 裡是什麼身份」
- `compiled policy` 決定「這些身份能做什麼」
- `resource attrs` 決定「這條規則是不是適用在這一筆 resource」
