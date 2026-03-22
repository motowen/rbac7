# ABAC+OPA Service System Specification

## 1. 系統概述 (Overview)

ABAC+OPA (Attribute-Based Access Control + Open Policy Agent 概念) 服務是為了提供高彈性、細粒度存取控制而設計的新一代權限管理系統。與傳統的 RBAC 相比，ABAC 允許基於主體 (Subject)、資源 (Resource)、操作 (Action) 以及環境的任意屬性 (Attributes) 進行權限決策。

本服務借鑑了 OPA 的設計思想：
- **宣告式策略 (Declarative Policies)**：規則存在資料庫中，可動態管理。
- **資料與邏輯解耦**：權限決策引擎 (`Engine`) 與業務系統分離。資源資料由呼叫方 (Caller) 在運行時傳入，而不在本服務中落地。

## 2. 核心模型 (Core Models)

### 2.1 主體 (Subject)
由 ABAC 服務負責維護與存儲 (MongoDB)。
- **UserID (`user_id`)**: 唯一識別碼。
- **Role (`role`)**: 基礎角色 (如 `admin`, `editor`, `viewer`)。
- **Status (`status`)**: 帳號狀態 (如 `active`, `suspended`)。
- **SensitivityLevel (`sensitivity_level`)**: 機密等級。
- **Orgs (`orgs`)**: 組織歸屬列表 (含 `org_id` 與 `org_type`)。
- **GroupIDs (`group_ids`)**: 所屬的群組 ID 列表。
- **CustomAttrs (`custom_attrs`)**: 自定義屬性 (Key-Value 格式，支援 `custom.xxx` 存取)。

### 2.2 資源 (Resource)
**不儲存在 ABAC 服務中**，而是在每次權限檢查 (`CheckAccess`) 時由呼叫方傳入。
- **ResourceID (`resource_id`), ResourceType (`resource_type`)**: 資源識別。
- **OwnerID (`owner_id`)**: 擁有者。
- **AllowedGroupIDs (`allowed_group_ids`)**: 白名單群組。若設定，主體必須至少屬於其中一個群組。
- **DeniedGroupIDs (`denied_group_ids`)**: 黑名單群組。若設定，主體若屬於其中任何一個群組，將立即被拒絕。
- **CustomAttrs (`custom_attrs`)**: 自定義屬性，供進階條件比對使用。

### 2.3 策略規則 (Policy Rule)
存儲於資料庫，動態管理。
- **ResourceType, Action**: 規則適用的資源類型與操作。
- **Effect**: `allow` 或 `deny`。
- **Priority**: 優先級 (數字越大優先級越高)。
- **Conditions**: 條件集合 (包含 `Subject` 與 `Resource` 條件)。
  - **欄位 (Field)**: 可指定的屬性欄位 (如 `status`, `role`, `custom.team`)。
  - **操作符 (Operator)**: 支援 `eq`, `neq`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `contains`。
  - **預期值 (Value)**: 比對的目標值。

### 2.4 屬性定義 (Attribute Definition)
可選的 Schema 定義，幫助前端或管理系統了解有哪些可用屬性。
- 定義 `Key`, `Scope` (subject/resource), `Type` (string/number/enum/bool), `Operators` 與 `AllowedValues` (針對 enum)。

## 3. 權限決策引擎邏輯 (Policy Engine Logic)

當呼叫 `CheckAccess` API 時，`Engine` 遵循以下嚴格的決策流程：

**1. 群組黑名單檢查 (Deny List Check)**
   - 若 `resource.denied_group_ids` 不為空。
   - 檢查 Subject 的 `group_ids` 是否與之有交集。
   - **若有交集：立即返回 Deny** (最高優先級)。

**2. 群組白名單檢查 (Allow List Check)**
   - 若 `resource.allowed_group_ids` 不為空。
   - 檢查 Subject 的 `group_ids` 是否與之有交集。
   - **若無交集 (或主體無群組)：立即返回 Deny**。

**3. 載入策略規則 (Load Policy Rules)**
   - 根據 `resource_type` 與 `action` 從資料庫載入所有啟用的 (Enabled) 策略規則。
   - 這些規則已根據 `priority` 由高至低排序。

**4. 評估策略規則 (Evaluate Rules - Priority-based & Deny-first)**
   - 依序評估每一優先級 (Priority) 群組的規則。
   - 針對同一 Priority 內的規則：
     - 若條件皆符合，收集匹配到的 `allow` 與 `deny` 規則。
     - **Deny-first 原則**：在同一 Priority 內，只要有任何一條 `deny` 規則命中，**立即返回 Deny**。
     - 若無 `deny` 命中，但有 `allow` 命中，**立即返回 Allow** (不再檢查較低 Priority)。
   - 若該 Priority 內無任何規則命中，則進入下一個 (較低的) Priority 繼續評估。

**5. 預設結果 (Default Deny)**
   - 若所有規則皆評估完畢，沒有任何規則命中，則**預設返回 Deny** (Default Deny 原則)。

## 4. 系統架構圖 (Architecture Diagram)

```text
HTTP Request (Caller / Middleware)
       |
       v
+------------------+
|      Handler     | (Request binding, validation)
+------------------+
       |
       v
+------------------+
|      Service     | (Orchestration, CRUD logic)
+------------------+
    /         \
   v           v
+--------+  +---------+
| Policy |  | Subject | (MongoDB Data Access)
|  Repo  |  |  Repo   |
+--------+  +---------+
    \         /
     \       / (Load subjective rules & data)
      v     v
+------------------+
|  Policy Engine   | -> Eval Conditions -> Output: Allowed (true/false)
+------------------+
```

## 5. 資料庫設計 (MongoDB)

本服務使用獨立的 MongoDB Collection：

### 5.1 `subjects` (Collection)
- Indexes:
  - `user_id` (Unique)
  - `group_ids`
  - `orgs.org_id`
  - `role`
  - `status`

### 5.2 `policy_rules` (Collection)
- Indexes:
  - `{ resource_type: 1, action: 1, enabled: 1 }` (查詢加速)
  - `priority: -1` (排序加速)

### 5.3 `attribute_definitions` (Collection)
- Indexes:
  - `{ key: 1, scope: 1 }` (Unique)
  - `{ scope: 1, resource_type: 1 }`

## 6. 與現有 RBAC 共存策略

- ABAC 服務設計為完全獨立的模組 (`internal/abac/`)，擁有自己的 HTTP 路由 (如 `/api/v1/access/...`)。
- 底層 MongoDB Collection 獨立 (不會與 `user_roles` 混用)。
- 目前僅聚焦於 resource scope 的細粒度控制，系統級權限 (System Scope) 若有需求，可另行透過 ABAC rules 或共用 RBAC 機制實作。
