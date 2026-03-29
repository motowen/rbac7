# 空間授權設計 (ABAC + OPA, 方案 B)

## 狀態

已批准的設計草案，用於實施規劃。

## 日期

2026-03-29

## 摘要

本設計引入了使用由 OPA 支持的混合 ABAC 模型的空間範圍授權 (space-scoped authorization)。

核心方法是：

- `Space BE` 擁有空間的可人工編輯授權模型。
- `Auth Platform` 擁有授權決策執行的權限。
- `OrgUser` 資料每天同步到 `Auth Platform` 作為本機快照。
- `FE` 不會直接呼叫原始權限檢查 API。
- `Space BE` 和 `Resource BE` 向 `FE` 暴露能力快照 (capability snapshot) API。
- `Resource BE` 負責候選資源查詢，以及在資料變更前執行嚴格強制授權。

此設計刻意不採用純 RBAC 系統，也不採用將「每個資源的 ACL 儲存在授權服務中」的純粹設計。這是一個實用的 ABAC 設計，將角色、群組、組織和資源元資料正規化為屬性，並在決策階段由 OPA 進行評估。

## 目標

- 支援空間層級 (space-level) 授權。
- 支援基於群組 (group-based) 的授權。
- 支援基於組織 (org-based) 的授權。
- 支援資源類型 (resource-type) 和資源實例 (resource-instance) 授權。
- 支援頻道層級 (channel-level) 的覆寫行為。
- 支援 FE 能力渲染，而無需 FE 直接呼叫原始決策 API。
- 將「查詢可用資源」保持在 `Resource BE` 中，而非 `Auth Platform`。
- 將熱路徑 (hot-path) 授權資料保存在 `Auth Platform` 內。

## 非目標

- 建立新的身分驗證系統。
- 將資源主資料移入 `Auth Platform`。
- 讓 `Auth Platform` 成為空間群組或權限矩陣編輯 UI 的真實資料來源。
- 在此階段實作組織資料的即時或每月同步。預設為每日同步。

## 假設條件

- 身分驗證由另一個團隊負責。
- `Auth Platform` 能夠透過外部身分/驗證平台來驗證傳入的使用者權杖 (token)。
- `OrgUser` 來源資料由另一個團隊負責，並每天同步到 `Auth Platform`。
- `Space BE` 是以下項目的真實來源 (source of truth)：
  - 空間成員
  - 群組主資料
  - 空間範圍的主體綁定 (principal bindings)
  - 權威權限矩陣 (canonical permission matrix)
- `Resource BE` 是資源元資料的真實來源。
- `FE` 需要的是能力快照，而不是原始決策 API。

## 架構

### 職責劃分

| 元件 | 職責 |
|---|---|
| `FE` | 使用後端 API 回傳的能力快照渲染 UI |
| `Space BE` | 管理成員、群組、空間權威策略，編譯策略投影 (policy projections)，暴露空間/頁面能力 API |
| `Resource BE` | 查詢候選資源，載入資源屬性，呼叫 `Auth Platform` 進行批次決策，強制執行寫入授權 |
| `Auth Platform` | 驗證權杖，載入本機授權資料，執行 OPA 決策，回傳允許(allow)/拒絕(deny) |
| `Org Source` | 組織屬性的真實來源 |

### PAP / PDP / PIP / PEP 映射

| 角色 | 元件 |
|---|---|
| `PAP` | `Space BE` |
| `PDP` | `Auth Platform` + OPA |
| `PIP` | `org_user_snapshots`, `space_principal_bindings`, 來自 `Resource BE` 的資源屬性 |
| `PEP` | `Space BE` 與 `Resource BE` |

## 資料所有權

| 資料 | 真實來源 | 儲存於 Auth Platform | 備註 |
|---|---|---:|---|
| 組織使用者 (OrgUser) | 組織來源系統 | 是 | 每日同步的快照 |
| 空間群組主資料 | Space BE | 否 | 名稱、描述、生命週期、UI 狀態保留在 Space BE 中 |
| 空間主體綁定 | Space BE | 是 | 已編譯的投影，用於決策熱路徑 |
| 權威權限矩陣 | Space BE | 否 | 可人工編輯的表示形式 |
| 已編譯的空間策略 | Space BE 編譯，Auth 儲存 | 是 | 決策階段的規則資料 |
| 資源主資料 | Resource BE | 否 | 在檢查時傳入 |

## 資料模型

### 1. `org_user_snapshots`

目的：

- 用於決策評估的組織屬性的本機副本。

建議 Schema 結構：

```json
{
  "user_id": "u_123",
  "function_ids": ["func_a", "func_b"],
  "division_id": "div_1",
  "dept_id": "dept_9",
  "sect_id": "sect_3",
  "employment_status": "active",
  "source_updated_at": "2026-03-29T00:00:00Z",
  "synced_at": "2026-03-29T01:00:00Z"
}
```

建議索引：

- `(user_id)` 唯一 (unique)
- `(division_id)`
- `(dept_id)`
- `(sect_id)`

### 2. `space_principal_bindings`

目的：

- 表示哪些主體 (principals) 被授予了哪些空間範圍的身分。
- 支援 `user` 和 `org` 主體。

主體類型：

- `user`
- `org`

建議 Schema 結構：

```json
{
  "space_id": "design",
  "principal_type": "user",
  "principal_id": "u_123",
  "grant_tokens": [
    "space:design:role:member",
    "space:design:group:backend",
    "space:design:group:reviewers"
  ],
  "binding_version": 42,
  "source_updated_at": "2026-03-29T09:15:00Z",
  "updated_at": "2026-03-29T09:15:01Z"
}
```

組織綁定範例：

```json
{
  "space_id": "design",
  "principal_type": "org",
  "principal_id": "dept_9",
  "grant_tokens": [
    "space:design:role:member"
  ],
  "binding_version": 43,
  "source_updated_at": "2026-03-29T09:16:00Z",
  "updated_at": "2026-03-29T09:16:01Z"
}
```

建議索引：

- `(space_id, principal_type, principal_id)` 唯一
- `(space_id, binding_version)`

### 3. `space_policy_manifests`

目的：

- 追蹤每個空間的當前活躍的編譯策略版本。

建議 Schema 結構：

```json
{
  "space_id": "design",
  "active_policy_version": 17,
  "compiler_version": "v1",
  "published_at": "2026-03-29T09:20:00Z",
  "source_matrix_version": 23,
  "checksum": "sha256:...",
  "status": "active"
}
```

建議索引：

- `(space_id)` 唯一

### 4. `space_policy_rule_sets`

目的：

- 儲存依據 `(space_id, policy_version, resource_type, action)` 分組的、供 OPA 消費的策略資料。
- 避免在每次決策時載入整個空間的策略文件。

建議 Schema 結構：

```json
{
  "space_id": "design",
  "policy_version": 17,
  "resource_type": "channel",
  "action": "post_message",
  "default_effect": "deny",
  "compiled_at": "2026-03-29T09:20:00Z",
  "rules": [
    {
      "rule_id": "r_001",
      "source_kind": "channel_override",
      "source_ref": "channel:general:contributor:post_message",
      "effect": "deny",
      "priority": 1000,
      "target_scope": "instance",
      "target_resource_id": "general",
      "principal_any": ["space:design:role:contributor"],
      "subject_conditions": [],
      "resource_conditions": [],
      "env_conditions": [],
      "enabled": true
    }
  ]
}
```

建議索引：

- `(space_id, policy_version, resource_type, action)` 唯一
- `(space_id, resource_type, action)`

### 5. 資源屬性 (Resource Attributes)

目的：

- 由 `Resource BE` 傳入的執行時期屬性。

建議 Schema 結構：

```json
{
  "space_id": "design",
  "resource_id": "doc_1",
  "resource_type": "document",
  "resource_parent_id": "",
  "owner_id": "u_456",
  "classification": "restricted",
  "visibility": "space",
  "allowed_group_ids": ["reviewers"],
  "denied_group_ids": [],
  "inherit_from_space": true
}
```

## Token 模型

### 身分權杖 (Identity Tokens)

身分權杖代表直接主體。

範例：

- `space:{space_id}:user:{user_id}`
- `space:{space_id}:org:{org_id}`

### 授權權杖 (Grant Tokens)

授權權杖代表策略規則所引用的有效身分。

範例：

- `space:{space_id}:role:{role}`
- `space:{space_id}:group:{group_id}`

### 為何這兩者同時存在

身分權杖回答：

- 誰是主體？

授權權杖回答：

- 該主體被授予了哪些空間範圍的角色和群組？

這種分離將主體解析和策略評估解耦。

## 有效主體解析 (Effective Subject Resolution)

在決策階段，`Auth Platform` 建構的有效主體如下：

1. 驗證權杖並萃取 `user_id`。
2. 載入 `org_user_snapshot`。
3. 從組織快照中推導出組織主體。
4. 產生這些項目的身分權杖：
   - 使用者
   - 每個相關的組織識別碼
5. 針對這些主體載入所有 `space_principal_bindings`。
6. 將所有 `grant_tokens` 聯集 (union)。
7. 從授權權杖推導出 `group_ids`。
8. 將資料組合成 OPA 的 subject 輸入格式。

有效主體範例：

```json
{
  "user_id": "u_123",
  "status": "active",
  "org": {
    "function_ids": ["func_a", "func_b"],
    "division_id": "div_1",
    "dept_id": "dept_9",
    "sect_id": "sect_3"
  },
  "principal_tokens": [
    "space:design:user:u_123",
    "space:design:org:dept_9",
    "space:design:role:member",
    "space:design:group:reviewers"
  ],
  "group_ids": ["reviewers"]
}
```

## Space BE 中的權威策略模型

`Space BE` 儲存可人工編輯的授權模型。

此權威模型應包含：

- 角色 (roles)
- 動作 (actions)
- 資源類型 (resource types)
- 權限矩陣 (permission matrix)
- 群組規則 (group rules)
- 組織規則 (org rules)
- 資源實例覆寫 (resource-instance overrides)
- 頻道專屬覆寫 (channel-specific overrides)
- 繼承行為 (inheritance behavior)

權威策略範例：

```json
{
  "space_id": "design",
  "matrix_version": 23,
  "roles": ["owner", "admin", "member", "guest", "contributor"],
  "permissions": [
    {
      "resource_type": "document",
      "action": "read",
      "cells": {
        "owner": "allow",
        "admin": "allow",
        "member": "allow",
        "guest": "inherit",
        "contributor": "inherit"
      }
    }
  ],
  "group_rules": [
    {
      "resource_type": "document",
      "action": "read",
      "when": {
        "classification": "restricted"
      },
      "allow_groups": ["reviewers"]
    }
  ],
  "org_rules": [
    {
      "resource_type": "space",
      "action": "view",
      "allow_org_ids": ["dept_9"]
    }
  ],
  "resource_overrides": [
    {
      "resource_type": "channel",
      "resource_id": "general",
      "action": "post_message",
      "cells": {
        "contributor": "deny"
      }
    }
  ]
}
```

## 權限矩陣 -> 已編譯的 ABAC 策略

### 編譯目標

- 將可人工編輯的矩陣資料轉換為執行階段的決策規則。
- 保持 Rego 靜態和通用。
- 以資料的形式儲存策略，而非產生的程式碼。
- 將 UI 專屬概念解析為確定性、相容於 OPA 的結構。

### 編譯輸出格式

編譯器輸出包含：

- 不可變的 `policy_version`
- 依據 `(space_id, policy_version, resource_type, action)` 分組的規則集 (rule sets)
- 確定性的 `rule_id`
- 一致的優先順序和衝突語意

### 三態語意 (Tri-State Semantics)

每個權限矩陣的單元格皆為以下之一：

- `allow`
- `deny`
- `inherit`

編譯語意：

- `allow` -> 產出 allow 規則
- `deny` -> 產出 deny 規則
- `inherit` -> 在此分層不產出任何規則

`inherit` 本身永遠不會產出 allow 規則。

### 建議的優先順序模型

| 規則來源 | 效果 | 優先順序 |
|---|---|---:|
| 實例覆寫 (Instance override) | deny | 1000 |
| 實例覆寫 | allow | 950 |
| 條件式組織/群組規則 | deny | 900 |
| 條件式组织/群組規則 | allow | 850 |
| 角色矩陣規則 | deny | 800 |
| 角色矩陣規則 | allow | 750 |
| 實體化回退 (Materialized fallback) | deny | 700 |
| 實體化回退 | allow | 650 |
| 預設 (Default) | deny | 0 |

衝突處理方式：

- 優先順序較高者獲勝。
- 若優先順序相同，則優先選擇 `deny`。
- 編譯器應拒絕從同一來源列產出相互矛盾的規則。

### 編譯規則 1：空間層級動作

範例：

- `space.view`
- `space.manage_members`
- `space.manage_groups`
- `space.manage_permissions`

編譯方式：

- `resource_type = "space"`
- `action = "{action_name}"`
- `target_scope = "type"`
- `target_resource_id = null`

範例：

UI 矩陣：

- `Admin` 允許 (allow) `space.manage_members`

編譯的規則：

```json
{
  "resource_type": "space",
  "action": "manage_members",
  "effect": "allow",
  "priority": 750,
  "principal_any": ["space:design:role:admin"],
  "subject_conditions": [],
  "resource_conditions": [],
  "source_kind": "role_matrix"
}
```

### 編譯規則 2：資源類型動作

範例：

- `document.read`
- `document.delete`
- `file.create`
- `task.update`
- `channel.post_message`

編譯方式：

- 每個 `allow` 或 `deny` 單元格都會變成一條規則
- `inherit` 不產出規則
- 規則會根據該資源類型和動作被歸入相對應的規則集

範例：

UI 矩陣：

- `Member` 允許 `document.read`
- `Admin` 允許 `document.delete`

編譯的規則：

```json
{
  "resource_type": "document",
  "action": "read",
  "effect": "allow",
  "priority": 750,
  "principal_any": ["space:design:role:member"],
  "source_kind": "role_matrix"
}
```

```json
{
  "resource_type": "document",
  "action": "delete",
  "effect": "allow",
  "priority": 750,
  "principal_any": ["space:design:role:admin"],
  "source_kind": "role_matrix"
}
```

### 編譯規則 3：頻道覆寫與資源實例覆寫

範例：

- `general` 頻道拒絕 `Contributor` 執行 `post_message`
- 單一份特定文件僅對審閱者群組可見

編譯方式：

- `target_scope = "instance"`
- `target_resource_id = 特定資源 ID`
- 覆寫的優先順序必須高於類型層級規則

範例：

權威覆寫來源：

- `channel:general`, `post_message`, `contributor = deny`

編譯的規則：

```json
{
  "resource_type": "channel",
  "action": "post_message",
  "effect": "deny",
  "priority": 1000,
  "target_scope": "instance",
  "target_resource_id": "general",
  "principal_any": ["space:design:role:contributor"],
  "source_kind": "channel_override"
}
```

覆寫單元格為 `inherit` 時表示：

- 不產出實例規則
- 回退 (fall back) 至資源類型規則的評估

如果 UI 支援「從其他頻道複製設定」，則必須在編譯前由 `Space BE` 解析這個複製關係。`Auth Platform` 只應接收攤平 (flattened) 後的規則。

### 編譯規則 4：群組規則

群組支援分為兩個獨立的職責。

群組成員身分：

- 作為 `grant_tokens` 儲存在 `space_principal_bindings` 中
- 不作為策略規則產出

基於群組的權限：

- 作為編譯後的策略規則產出

範例：

權威規則來源：

- `reviewers` 群組可以讀取受限制的 (restricted) 文件

編譯的規則：

```json
{
  "resource_type": "document",
  "action": "read",
  "effect": "allow",
  "priority": 850,
  "principal_any": ["space:design:group:reviewers"],
  "resource_conditions": [
    { "field": "classification", "operator": "eq", "value": "restricted" }
  ],
  "source_kind": "group_rule"
}
```
### 編譯規則 5：組織規則

組織支援同樣分為兩個獨立的職責。

組織主體綁定：

- 儲存在 `space_principal_bindings` 中
- 用於從組織成員身分推導出角色/群組身分

基於組織的權限：

- 作為編譯後的策略規則產出

範例 A：

權威綁定來源：

- `dept_9` 以 `member` 身分進入空間

編譯的綁定：

```json
{
  "space_id": "design",
  "principal_type": "org",
  "principal_id": "dept_9",
  "grant_tokens": ["space:design:role:member"]
}
```

範例 B：

權威權限來源：

- `dept_9` 的成員可以執行 `space.view`

編譯的規則：

```json
{
  "resource_type": "space",
  "action": "view",
  "effect": "allow",
  "priority": 850,
  "principal_any": ["space:design:org:dept_9"],
  "source_kind": "org_rule"
}
```

### 編譯管線 (Compile Pipeline)

1. 從 `Space BE` 載入權威策略。
2. 驗證角色、群組、組織 ID、資源類型以及動作。
3. 解析 `copy` (複製) 關係。
4. 將三態 (tri-state) 單元格展開為明確的候選規則。
5. 將角色/群組/組織目標轉換為權杖 (token) 參照。
6. 根據來源類型和效果 (effect) 分配優先順序。
7. 產生確定性的 `rule_id` 值。
8. 依據 `(resource_type, action)` 將規則分組。
9. 將所有分好組的規則集發布到 `Auth Platform` 作為草案策略版本。
10. 以原子 (atomic) 方式啟用該版本。

### 編譯器驗證規則

- 拒絕未知的 `resource_type`。
- 拒絕未知的動作 (action) 鍵。
- 拒絕未知的 `group_id`。
- 拒絕未知的 `org_id`。
- 當啟用嚴格驗證時，拒絕參照了不存在之資源 ID 的覆寫規則。
- 拒絕從同一權威資料列產出相互矛盾的 allow 和 deny 規則。
- 要求已發布的策略版本必須是不可變的 (immutable)。

## 建議的 `space_policy_projection` Schema 結構

建議的 Schema 由兩部分組成：

- 用於追蹤版本的清單 (manifest) 文件
- 供執行時期載入、分組好的規則集文件

### 清單 (Manifest)

```json
{
  "space_id": "design",
  "active_policy_version": 17,
  "compiler_version": "v1",
  "source_matrix_version": 23,
  "checksum": "sha256:compiled-policy-checksum",
  "published_at": "2026-03-29T09:20:00Z",
  "status": "active"
}
```

### 規則集 (Rule Set)

```json
{
  "space_id": "design",
  "policy_version": 17,
  "resource_type": "document",
  "action": "read",
  "default_effect": "deny",
  "compiled_at": "2026-03-29T09:20:00Z",
  "rules": [
    {
      "rule_id": "role-matrix-document-read-member",
      "source_kind": "role_matrix",
      "source_ref": "matrix:document:read:member",
      "effect": "allow",
      "priority": 750,
      "target_scope": "type",
      "target_resource_id": null,
      "principal_any": ["space:design:role:member"],
      "subject_conditions": [],
      "resource_conditions": [],
      "env_conditions": [],
      "enabled": true
    },
    {
      "rule_id": "group-rule-document-read-reviewers-restricted",
      "source_kind": "group_rule",
      "source_ref": "group_rule:reviewers:document:read",
      "effect": "allow",
      "priority": 850,
      "target_scope": "type",
      "target_resource_id": null,
      "principal_any": ["space:design:group:reviewers"],
      "subject_conditions": [],
      "resource_conditions": [
        { "field": "classification", "operator": "eq", "value": "restricted" }
      ],
      "env_conditions": [],
      "enabled": true
    }
  ]
}
```

### 規則欄位 (Rule Fields)

| 欄位 | 意義 |
|---|---|
| `rule_id` | 確定性的識別碼 |
| `source_kind` | `role_matrix`, `group_rule`, `org_rule`, `channel_override`, `resource_override` |
| `source_ref` | 可追溯回權威來源的參照連結 |
| `effect` | `allow` 或 `deny` |
| `priority` | 數值優先順序 |
| `target_scope` | `type` 或 `instance` |
| `target_resource_id` | 實例層級規則的特定資源 ID |
| `principal_any` | 只要有任何相符的主體權杖，即符合規則條件 |
| `subject_conditions` | 額外的主體限制條件 |
| `resource_conditions` | 額外的資源限制條件 |
| `env_conditions` | 未來的擴充點 (環境條件) |
| `enabled` | 規則開啟/關閉的旗標 |

## 決策模型

### 輸入

決策評估的輸入包含：

- `subject`
- `resource`
- `action`
- `rule_set`

建議的輸入格式：

```json
{
  "subject": {
    "user_id": "u_123",
    "status": "active",
    "org": {
      "function_ids": ["func_a", "func_b"],
      "division_id": "div_1",
      "dept_id": "dept_9",
      "sect_id": "sect_3"
    },
    "principal_tokens": [
      "space:design:user:u_123",
      "space:design:org:dept_9",
      "space:design:role:member",
      "space:design:group:reviewers"
    ],
    "group_ids": ["reviewers"]
  },
  "resource": {
    "space_id": "design",
    "resource_id": "doc_1",
    "resource_type": "document",
    "owner_id": "u_456",
    "classification": "restricted",
    "visibility": "space",
    "allowed_group_ids": ["reviewers"],
    "denied_group_ids": []
  },
  "action": "read",
  "rule_set": {}
}
```

### 評估順序

1. 驗證 `space_id`、`resource_type` 和 `action`。
2. 載入當前活躍的 `policy_version`。
3. 載入相符的 `rule_set`。
4. 依據 `target_scope` 過濾規則：
   - 尋找符合 `resource_id` 的 instance (實例) 規則
   - 尋找 type (類型) 規則
5. 將 `principal_any` 與 `subject.principal_tokens` 進行比對。
6. 評估主體條件 (subject conditions)。
7. 評估資源條件 (resource conditions)。
8. 若存在，評估環境條件 (env conditions)。
9. 依據優先順序選出獲勝的規則。
10. 在優先順序相同時，優先選擇 `deny`。
11. 回退到 `default_effect` (預設效果)。

## 能力快照 APIs (Capability Snapshot APIs)

`FE` 不會直接呼叫原始的決策 API。

`Space BE` 和 `Resource BE` 會將原始的分散式決策結果轉換為易於 FE 使用的能力快照。

### 1. 空間層級能力

端點 (Endpoint)：

```text
GET /api/spaces/{space_id}/me/capabilities
```

回應 (Response)：

```json
{
  "space_id": "design",
  "policy_version": 17,
  "capabilities": {
    "space.view": true,
    "space.manage_members": false,
    "space.manage_groups": false,
    "space.manage_permissions": false,
    "document.create": true,
    "file.create": true,
    "task.create": false,
    "channel.create": true,
    "audit_log.view": false
  }
}
```

### 2. 資源類型能力

端點：

```text
POST /api/spaces/{space_id}/me/resource-type-capabilities
```

請求 (Request)：

```json
{
  "resource_types": ["document", "file", "task", "channel"],
  "actions": ["create", "read", "update", "delete", "manage_permissions"]
}
```

回應：

```json
{
  "space_id": "design",
  "capabilities": {
    "document": { "create": true, "read": true, "update": true, "delete": false },
    "file": { "create": true, "read": true, "update": false, "delete": false },
    "task": { "create": false, "read": true, "update": false, "delete": false },
    "channel": { "create": true, "read": true, "update": false, "delete": false }
  }
}
```

### 3. 資源實例能力

端點：

```text
POST /api/spaces/{space_id}/me/resource-instance-capabilities
```

請求：

```json
{
  "resources": [
    { "resource_id": "doc_1", "resource_type": "document" },
    { "resource_id": "doc_2", "resource_type": "document" },
    { "resource_id": "ch_1", "resource_type": "channel" }
  ],
  "actions": ["read", "update", "delete", "manage_permissions"]
}
```

回應：

```json
{
  "space_id": "design",
  "results": {
    "doc_1": { "read": true, "update": true, "delete": false, "manage_permissions": false },
    "doc_2": { "read": true, "update": false, "delete": false, "manage_permissions": false },
    "ch_1": { "read": true, "update": false, "delete": false, "manage_permissions": true }
  }
}
```

## 內部 Auth Platform APIs

這些是僅供後端使用的 API。

### 組織同步 (Org Sync)

```text
PUT /v2/internal/org-users/batch
```

### 主體綁定投影 (Principal Binding Projection)

```text
PUT /v2/internal/spaces/{space_id}/bindings/batch
```

### 策略投影上傳 (Policy Projection Upload)

```text
PUT /v2/internal/spaces/{space_id}/policies/{policy_version}/rule-sets
POST /v2/internal/spaces/{space_id}/policies/{policy_version}/activate
```

### 原始決策 APIs

```text
POST /v2/internal/decisions/check
POST /v2/internal/decisions/check/batch
```

## 循序圖 (Sequence Diagrams)

### 序列 1：每日 OrgUser 同步

```mermaid
sequenceDiagram
    participant OrgSource as 組織團隊來源
    participant SyncJob as 同步任務
    participant Auth as Auth Platform

    OrgSource->>SyncJob: 匯出 OrgUser 資料
    SyncJob->>Auth: PUT /internal/org-users/batch
    Auth->>Auth: 更新/插入 (upsert) org_user_snapshots
    Auth-->>SyncJob: 成功 + 同步數量
```

### 序列 2：儲存空間權限矩陣並發布編譯策略

```mermaid
sequenceDiagram
    participant FE
    participant SpaceBE
    participant Auth as Auth Platform

    FE->>SpaceBE: 儲存成員/群組/權限矩陣
    SpaceBE->>SpaceBE: 持久化權威綁定與權威策略
    SpaceBE->>SpaceBE: 驗證策略參照
    SpaceBE->>SpaceBE: 將矩陣編譯為分好組的 rule_sets
    SpaceBE->>Auth: PUT bindings/batch (binding_version=42)
    Auth->>Auth: 更新/插入 space_principal_bindings
    SpaceBE->>Auth: PUT policies/17/rule-sets
    Auth->>Auth: 儲存草案 rule_sets
    SpaceBE->>Auth: POST policies/17/activate
    Auth->>Auth: 以原子方式更新 active_policy_version
    Auth-->>SpaceBE: 成功 + 當前活躍 policy_version=17
    SpaceBE-->>FE: 成功
```

### 序列 3：FE 載入空間 UI 能力快照

```mermaid
sequenceDiagram
    participant FE
    participant SpaceBE
    participant Auth as Auth Platform
    participant Verify as 身分驗證器

    FE->>SpaceBE: GET /spaces/design/me/capabilities
    SpaceBE->>Auth: 針對空間/頁面動作發起批次決策
    Auth->>Verify: 驗證權杖
    Verify-->>Auth: user_id
    Auth->>Auth: 載入 org_user_snapshot
    Auth->>Auth: 推導出組織主體
    Auth->>Auth: 載入 space_principal_bindings
    Auth->>Auth: 建構有效主體 (effective subject)
    Auth->>Auth: 載入當前活躍的空間策略清單
    Auth->>Auth: 載入 rule_sets(resource_type=space 及頁面層級動作)
    Auth->>Auth: OPA 評估
    Auth-->>SpaceBE: 原始決策 Map
    SpaceBE->>SpaceBE: 將原始決策對應為能力快照
    SpaceBE-->>FE: 能力快照
```

### 序列 4：FE 載入資源清單和資料列層級的動作

```mermaid
sequenceDiagram
    participant FE
    participant ResourceBE
    participant ResourceDB
    participant Auth as Auth Platform
    participant Verify as 身分驗證器

    FE->>ResourceBE: GET /documents?page=1
    ResourceBE->>ResourceDB: 以過濾條件和分頁查詢候選文件
    ResourceDB-->>ResourceBE: 文件頁面 + 資源屬性
    ResourceBE->>Auth: 針對 doc_1..doc_n 及動作=[read,update,delete] 發起批次決策
    Auth->>Verify: 驗證權杖
    Verify-->>Auth: user_id
    Auth->>Auth: 載入組織快照
    Auth->>Auth: 解析主體 (單次)
    Auth->>Auth: 載入綁定 (單次)
    Auth->>Auth: 建構有效主體 (單次)
    Auth->>Auth: 載入當前活躍的 rule_sets(document.read, update, delete)
    Auth->>Auth: 對每個資源進行 OPA 評估
    Auth-->>ResourceBE: 每個資源的原始決策
    ResourceBE->>ResourceBE: 建構實例能力快照
    ResourceBE-->>FE: 資源 + 能力快照
```

### 序列 5：針對寫入操作的嚴格強制執行 (Hard Enforcement)

```mermaid
sequenceDiagram
    participant FE
    participant ResourceBE
    participant ResourceDB
    participant Auth as Auth Platform

    FE->>ResourceBE: DELETE /documents/doc_1
    ResourceBE->>ResourceDB: 載入 doc_1 屬性
    ResourceDB-->>ResourceBE: doc_1 屬性
    ResourceBE->>Auth: 單一決策(document.delete, doc_1 屬性)
    Auth->>Auth: 解析有效主體
    Auth->>Auth: 載入當前活躍的 rule_set(document.delete)
    Auth->>Auth: OPA 評估
    Auth-->>ResourceBE: allow / deny
    alt allow
        ResourceBE->>ResourceDB: 刪除文件
        ResourceBE-->>FE: 200
    else deny
        ResourceBE-->>FE: 403
    end
```

### 序列 6：頻道覆寫範例

```mermaid
sequenceDiagram
    participant FE
    participant SpaceBE
    participant Auth as Auth Platform
    participant ResourceBE

    FE->>SpaceBE: 設定頻道 "general" 把 contributor.post_message = deny
    SpaceBE->>SpaceBE: 儲存權威頻道覆寫設定
    SpaceBE->>SpaceBE: 將覆寫編譯為實例規則 (instance rule)
    SpaceBE->>Auth: 發布更新後的 rule_set(channel.post_message)
    Auth-->>SpaceBE: 已啟用 policy_version=18

    FE->>ResourceBE: 在頻道 general 發布訊息
    ResourceBE->>Auth: 決策(channel.post_message, resource_id=general)
    Auth-->>ResourceBE: deny
    ResourceBE-->>FE: 403
```

## 效能設計

### 熱路徑需求 (Hot Path Requirements)

決策熱路徑應該只讀取：

- `org_user_snapshot`
- 相關的 `space_principal_bindings`
- 當前活躍的 `space_policy_manifest`
- 一個或多個 `space_policy_rule_sets`

### 建議的快取鍵 (Cache Keys)

- 有效主體快取：
  - `(space_id, user_id, binding_version, org_sync_version)`
- 規則集快取：
  - `(space_id, policy_version, resource_type, action)`

### 批次決策策略

針對批次檢查：

- 單次解析有效主體
- 單次載入所需的規則集
- 使用同一個規則集來評估每個資源實例

避免對每個資源項目重新載入策略規則。

### 查詢可用資源

`Auth Platform` 絕對不得負責候選資源的查詢。

正確流程：

1. `Resource BE` 從自己的資料庫查詢出一頁的候選資料。
2. `Resource BE` 呼叫 `Auth Platform` 進行批次決策。
3. `Resource BE` 回傳：
   - 過濾後的結果
   - 或是完整結果，並附帶每個項目的能力

如果結果集變得過大：

- 先進行分頁
- 僅授權當前頁面
- 避免因授權而導致全資料表掃描 (full table scans)

## 引擎需做出的變更

相對於目前的 code repository，實作上還需要：

- 新增依據 `space_id + resource_type + action` 去查找決策的功能
- 在 OPA subject 輸入中擴充：
  - `principal_tokens`
  - `org`
- 讓規則資料支援：
  - `principal_any`
  - `target_scope`
  - `target_resource_id`
- 針對組織屬性與主體權杖實作欄位解析器 (field resolvers)
- 不會對每個資源重新抓取規則資料的批次評估機制

## 開發清單

### 階段 1：資料結構

- 新增 `org_user_snapshots`
- 新增 `space_principal_bindings`
- 新增 `space_policy_manifests`
- 新增 `space_policy_rule_sets`

### 階段 2：投影 APIs

- 實作組織使用者批次同步 API
- 實作主體綁定投影 API
- 實作已編譯策略上傳 API
- 實作策略啟用 API

### 階段 3：決策引擎

- 擴充 OPA 輸入模型
- 擴充 Rego 欄位解析
- 新增透過 `(space_id, policy_version, resource_type, action)` 載入規則集的功能
- 實作實例覆寫處理機制

### 階段 4：Space BE 編譯器

- 定義權威策略 Schema 結構
- 驗證權威矩陣
- 將矩陣編譯為分組的規則集
- 發布草案版本
- 以原子方式啟用版本

### 階段 5：能力 APIs

- 實作 `Space BE` 能力端點
- 實作 `Resource BE` 實例能力端點
- 將原始決策結果對應成 FE 能力快照

### 階段 6：驗證

- 測試 使用者綁定 + 組織綁定 的聯集行為
- 測試 deny-over-allow (拒絕優先) 的機制
- 測試類型層級的 allow 遭遇實例層級的 deny 覆寫
- 測試基於群組的受限制文件存取控制
- 測試頻道覆寫行為
- 測試陳舊 (stale) 的 binding version 和 policy version 等邊緣情況

## 最終建議

利用 `Space BE` 作為策略編寫和編譯層，並將 `Auth Platform` 作為由 OPA 支持的執行時期決策引擎。

實作的關鍵原則是：

- 綁定決定了主體在空間中成為「誰」
- 編譯的策略決定了該主體可以做「什麼」
- 資源屬性決定了該規則是否適用於「這一個特定的資源實例」

這種職責劃分使系統保持與 OPA + ABAC 的一致性，同時仍能支援角色矩陣 UI、組織綁定、群組規則和資源覆寫，而不會將領域的擁有權推向 `Auth Platform` 中。
