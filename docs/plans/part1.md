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
