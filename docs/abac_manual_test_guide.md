# ABAC+OPA Service 手動測試流程指南

這份文件提供了一個完整的流程，讓你可以在本地端啟動 ABAC 服務後，使用 `curl` 進行端到端 (End-to-End) 的手動測試。

## 概念總結

在我們的實作中，OPA 的三大元素分別代表：

1. **Policy (Rego 策略)**：
   - 對應檔案：`internal/abac/policy/policies/abac.rego`
   - **角色**：大腦。裡面寫死了我們「群組優先、Priority排序、Deny-first、Default Deny」的核心判斷邏輯。
2. **Input (輸入參數)**：
   - 對應程式：`engine.go` 內的 `buildOPAInput` 函數
   - **角色**：提問單。每次檢查權限時動態產生，裡面包含了：
     - `subject` (誰？角色、狀態、群組)
     - `resource` (對什麼？類型、名單設定)
     - `action` (做什麼？)
     - `rules` (從 MongoDB 撈出來，跟這個 Resource/Action 相關的規則)
3. **Data (外部資料)**：
   - **角色**：在傳統 OPA 中，資料庫的規則通常會同步到 OPA 的 Data Store 裡。但在我們的設計中，為了確保無狀態 (Stateless) 與即時性，我們 **沒有使用 `data` 綁定**，而是直接將撈出來的 Rules 塞進 `input.rules` 當作 Input 餵給 OPA。

---

## 準備工作

1. 確保 MongoDB 已啟動：
   ```bash
   # 如果使用 Docker
   docker run -d -p 27017:27017 --name mongo mongo:latest
   ```

2. 啟動 ABAC 服務：
   ```bash
   # 設定環境變數並啟動 (預設 Port 通常為 8080)
   MONGO_URI="mongodb://localhost:27017" DB_NAME="abac_db" PORT="8080" go run ./cmd/server/main.go
   ```
   *(註：若您未建立 `cmd/abac/main.go`，可用您平常測試 API 的入口檔啟動 Go Server)*

---

## 步驟一：建立使用者 (Subject)

我們先建立一個身分為 `editor`，狀態為 `active`，屬於 `backend-team` 群組的使用者 `user_alice`。

```bash
curl -X POST http://localhost:8080/api/v1/subjects \
  -H "Content-Type: application/json" \
  -H "x-user-id: admin" \
  -d '{
    "user_id": "user_alice",
    "role": "editor",
    "status": "active",
    "sensitivity_level": "normal",
    "groups": ["backend-team"],
    "custom_attrs": [
      {
        "key": "department",
        "value": "engineering"
      }
    ]
  }'
```

---

## 步驟二：建立權限規則 (Policy Rule)

接下來，我們在資料庫中定義「允許 `role` 是 `editor` 的人可以 `update` 類型為 `document` 的資源」的規則。

```bash
curl -X POST http://localhost:8080/api/v1/policies/rules \
  -H "Content-Type: application/json" \
  -H "x-user-id: admin" \
  -d '{
    "name": "editors_can_update_docs",
    "resource_type": "document",
    "action": "update",
    "effect": "allow",
    "priority": 10,
    "enabled": true,
    "conditions": {
      "subject": [
        {
          "field": "role",
          "operator": "eq",
          "value": "editor"
        }
      ]
    }
  }'
```

---

## 步驟三：測試權限檢查 (Check Access)

### 情境 A：正常許可 (Expected: `allowed: true`)

Alice 想要 `update` 一份 `document`，由於符合我們剛剛建立的 Policy Rule，應該要 Allow。

```bash
curl -X POST http://localhost:8080/api/v1/access/check \
  -H "Content-Type: application/json" \
  -H "x-user-id: client" \
  -d '{
    "subject_id": "user_alice",
    "action": "update",
    "resource": {
      "resource_id": "doc_123",
      "resource_type": "document"
    }
  }'
```
**預期回應**：
```json
{
  "allowed": true,
  "reason": "allowed by rule: editors_can_update_docs"
}
```

### 情境 B：觸發 Default Deny (Expected: `allowed: false`)

Alice 想要執行 `delete` 操作，但資料庫中並沒有任何允許 delete 的規則。

```bash
curl -X POST http://localhost:8080/api/v1/access/check \
  -H "Content-Type: application/json" \
  -H "x-user-id: client" \
  -d '{
    "subject_id": "user_alice",
    "action": "delete",
    "resource": {
      "resource_id": "doc_123",
      "resource_type": "document"
    }
  }'
```
**預期回應**：
```json
{
  "allowed": false,
  "reason": "no matching policy rules"
}
```

### 情境 C：群組黑名單攔截 (Expected: `allowed: false`)

資源 `doc_456` 設定了 `denied_group_ids: ["backend-team"]`，而 Alice 剛好在這個群組內。這會觸發 Rego 裡最高優先級的「群組黑名單」防護，直接忽略其他 Rule。

```bash
curl -X POST http://localhost:8080/api/v1/access/check \
  -H "Content-Type: application/json" \
  -H "x-user-id: client" \
  -d '{
    "subject_id": "user_alice",
    "action": "update",
    "resource": {
      "resource_id": "doc_456",
      "resource_type": "document",
      "denied_group_ids": ["backend-team"]
    }
  }'
```
**預期回應**：
```json
{
  "allowed": false,
  "reason": "subject is in denied group"
}
```

### 情境 D：新增高優先級 Deny Rule 覆寫 (Expected: `allowed: false`)

我們先新增一條 Priority 更高的 Deny 規則：「工程部的人不能修改最高機密的檔案」

```bash
curl -X POST http://localhost:8080/api/v1/policies/rules \
  -H "Content-Type: application/json" \
  -H "x-user-id: admin" \
  -d '{
    "name": "deny_engineering_secret",
    "resource_type": "document",
    "action": "update",
    "effect": "deny",
    "priority": 99,
    "enabled": true,
    "conditions": {
      "subject": [
        {
          "field": "custom.department",
          "operator": "eq",
          "value": "engineering"
        }
      ],
      "resource": [
        {
          "field": "sensitivity_level",
          "operator": "eq",
          "value": "top_secret"
        }
      ]
    }
  }'
```

接著我們讓 Alice 去測試讀取 `sensitivity_level` 為 `top_secret` 的檔案：

```bash
curl -X POST http://localhost:8080/api/v1/access/check \
  -H "Content-Type: application/json" \
  -H "x-user-id: client" \
  -d '{
    "subject_id": "user_alice",
    "action": "update",
    "resource": {
      "resource_id": "doc_789",
      "resource_type": "document",
      "sensitivity_level": "top_secret"
    }
  }'
```
**預期回應**：
因為 Deny 規則 (Priority: 99) 大於原先的 Allow 規則 (Priority: 10)，所以會被拒絕。
```json
{
  "allowed": false,
  "reason": "denied by rule: deny_engineering_secret"
}
```
