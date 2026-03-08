# NATS 權限檢查策略分析：雙層檢查 vs 純 Auth Callout

## 方案 A：雙層檢查（推薦）

Auth Callout 做**粗粒度**的 subject 存取控制，NATS handler 裡仍透過 PolicyEngine 做**細粒度** RBAC 檢查。

```
FE ──connect(JWT)──▶ NATS Server
                        │
                        ▼ Auth Callout
                   RBAC Service 查角色
                   → 回傳粗粒度 NATS permissions
                   （例如 owner 可 pub rbac.system.NS1.>）
                        │
                        ▼
                   FE 已連線，只能存取被授權的 subjects
                        │
FE ──request──▶ rbac.system.assign_role
                        │
                        ▼ NATS Handler
                   1. 反序列化 request
                   2. PolicyEngine.CheckOperationPermission() ← 細粒度
                   3. Service.AssignSystemUserRole()
                   4. 回傳 response
```

### 優點
- ✅ **與現有 HTTP 行為完全一致** — 權限邏輯不需要改，100% 複用現有 PolicyEngine + 策略 JSON
- ✅ **即時生效** — 角色變更後，下一次 request 就會被正確檢查（不需要重新連線）
- ✅ **安全性高** — 兩道防線：NATS subject 過濾 + request-level RBAC
- ✅ **Auth Callout 邏輯簡單** — 只需粗略映射，不需要精確對應每個 operation

### 缺點
- ❌ **每次 request 都有 DB 查詢** — 和 HTTP middleware 一樣，每次都查 MongoDB 確認角色（可加 cache）
- ❌ **Auth Callout 的粗粒度 permissions 邏輯仍需維護**（但很簡單）

### 實作難度：⭐⭐（低）
- Auth Callout 的映射只需 ~50 行
- NATS handler 裡的 RBAC 檢查直接呼叫現有 `PolicyEngine.CheckOperationPermission()`
- 不需要重新設計權限模型

---

## 方案 B：純 Auth Callout 靜態權限

所有權限都在**連線時**一次性決定。Auth Callout 將 RBAC 角色精確映射為 NATS subject 級別的 publish/subscribe 權限，NATS handler 裡**不再做 RBAC 檢查**。

```
FE ──connect(JWT)──▶ NATS Server
                        │
                        ▼ Auth Callout
                   RBAC Service 查角色 + 查所有資源角色
                   → 精確映射每個 operation 對應的 subject
                   （例如 dashboard D1 的 editor 可 pub rbac.resource.assign_role
                     但只限 resource_id=D1 的請求）
                        │
                        ▼
                   FE 已連線，NATS 層面直接攔截無權 subject
                        │
FE ──request──▶ rbac.system.assign_role
                        │
                        ▼ NATS Handler
                   1. 反序列化 request（不檢查權限）
                   2. 直接呼叫 Service 方法
                   3. 回傳 response
```

### 優點
- ✅ **每次 request 不用查 DB** — 效能最佳，zero-overhead per request
- ✅ **NATS handler 極其簡單** — 純粹 serialize/deserialize + 呼叫 service

### 缺點
- ❌ **角色變更不即時生效** — 必須強制使用者重新連線（或用短 JWT expiry + 自動重連）
- ❌ **Auth Callout 邏輯非常複雜** — 需要精確建模所有場景：
  - Subject 設計需細到 `rbac.resource.assign_role.{resource_type}.{resource_id}` 才能做到資源級權限控制
  - `dashboard_widget` 的 parent_resource 繼承、`library_widget` 的 `public_if_no_roles`、Org 權限繼承等複雜邏輯都要翻譯成靜態 subject pattern
  - 50+ 個 resource 就有 50+ 個精確 subject permission，Auth Callout 回傳的 JWT 會非常大
- ❌ **無法完整表達現有 RBAC 邏輯** — 例如：
  - `dashboard_widget` 的繼承/白名單雙模式無法用靜態 subject 權限表達
  - Org 權限繼承需要在連線時查所有 org role
  - [CheckPermission](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#33-34) API（batch 檢查多資源）的動態性無法提前靜態化
- ❌ **維護成本高** — 兩套權限系統（JSON policy + NATS subject mapping）需保持同步
- ❌ **owner 保護機制難映射** — 唯一 owner 不可降級等動態檢查無法在 subject 層面實現

### 實作難度：⭐⭐⭐⭐⭐（高）
- 需要重新設計 subject 格式來表達資源級別的精確權限
- 需要處理 JWT token 過大的問題
- 現有的 Widget 繼承邏輯、Org 繼承等幾乎無法用 NATS static permissions 表達
- 角色變更觸發重連的機制需要額外開發

---

## 總結對比

| | 方案 A：雙層檢查 | 方案 B：純 Auth Callout |
|---|---|---|
| **實作難度** | ⭐⭐ 低 | ⭐⭐⭐⭐⭐ 高 |
| **與現有架構相容性** | ✅ 100% 複用 | ❌ 需大量重新設計 |
| **權限即時生效** | ✅ 每次 request 檢查 | ❌ 需重連 |
| **Per-request 效能** | 中（有 DB 查詢） | 高（zero-overhead） |
| **能否完整表達 RBAC 邏輯** | ✅ 完全可以 | ❌ Widget 繼承/Org 繼承難表達 |
| **Auth Callout 複雜度** | 低（~50 行映射） | 極高（500+ 行精確映射） |
| **安全性** | 高（雙層防線） | 中（單層靜態） |
| **新增資源類型時** | 不需改 Auth Callout | 需同步更新映射 |

> [!TIP]
> **強烈建議採用方案 A（雙層檢查）**。你現有的 RBAC 系統有很多動態邏輯（Widget 繼承、Org 權限、owner 保護等），這些都無法被靜態 NATS subject permissions 完整表達。方案 A 讓你以最小改動獲得 NATS 通道，而且如果以後想用快取優化 per-request DB 查詢，加一層 Redis/in-memory cache 就行。
