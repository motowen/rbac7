# RBAC System Complete Architecture Specification

> This document details the complete architecture, data models, API design, policy engine, business logic, and implementation details of the RBAC (Role-Based Access Control) system. The goal is to provide enough specification for an AI to regenerate the identical system functionality based on this document.

---

## 1. System Overview

### 1.1 Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.24.6 |
| HTTP Framework | Echo v4.14.0 |
| Database | MongoDB (mongo-driver v1.17.6) |
| Validation | go-playground/validator/v10 |
| Testing | testify v1.11.1 |

### 1.2 Project Structure

```text
rbac7/
├── cmd/server/main.go          # Application Entrypoint
├── docs/
│   ├── rbac.yaml               # OpenAPI 3.0.3 Specification
│   └── seed_org_system_roles.json
├── internal/rbac/
│   ├── config/config.go        # Environment Variables & Config
│   ├── handler/                # HTTP Handler Layer
│   │   ├── handler_common.go   # Common APIs (GetUserRoles, CheckPermission)
│   │   ├── handler_system.go   # System scope APIs
│   │   ├── handler_resource.go # Resource scope APIs
│   │   ├── rbac_middleware.go  # Policy-driven RBAC Middleware
│   │   ├── middleware.go       # RequestID Middleware
│   │   └── error.go           # Error mapping to HTTP responses
│   ├── model/                  # Data Models + Request DTOs + Validators
│   │   ├── types.go            # Core Types (UserRole, SystemUserRole, etc.)
│   │   ├── constants.go        # Roles/Permissions/Scopes Constants
│   │   ├── validator.go        # Validator Singleton
│   │   ├── user_role_history.go
│   │   ├── batch_upsert_result.go
│   │   └── *_req.go            # Request Validation Structs (14 Request Models)
│   ├── policy/                 # Policy Engine (Core)
│   │   ├── engine.go           # Permission Evaluation Engine
│   │   ├── loader.go           # JSON Policy Loader (embed.FS)
│   │   ├── types.go            # Policy Type Definitions
│   │   └── policies/           # Embedded JSON Policies
│   │       ├── operations/     # Entity Operation Policies (4 JSONs)
│   │       ├── roles/          # Role-Permission Mappings (2 JSONs)
│   │       └── check_permission.json # Inheritance Policies
│   ├── repository/             # Data Access Layer
│   │   ├── repository.go       # RBACRepository Interface
│   │   ├── history_repository.go
│   │   ├── org_user_repository.go
│   │   ├── mongo_common_impl.go
│   │   ├── mongo_system_impl.go
│   │   └── mongo_resource_impl.go
│   ├── router/router.go        # Route Registration
│   ├── service/                # Business Logic Layer
│   │   ├── service_common.go   # RBACService Interface + Common Logic
│   │   ├── service_system.go   # System scope logic
│   │   └── service_resource.go # Resource scope logic
│   └── util/logger.go
└── tests/                      # Integration Tests (22 files)
```

---

## 2. Core Concept Models

### 2.1 Dual Scope Architecture

The system is divided into two major scopes, **each using a separate MongoDB Collection**:

| Scope | Collection | Description |
|-------|------------|-------------|
| `system` | `user_roles` | Platform-level roles (bound to a `namespace`) |
| `resource` | `user_resource_roles` | Resource-level roles (bound to `resource_id` + `resource_type`) |

### 2.2 Role Hierarchy

#### System Roles (High → Low)

| Role | Priority | Description |
|------|----------|-------------|
| `moderator` | 6 | Super Admin, can only assign owners |
| `owner` | 5 | Namespace Owner, can manage members fully |
| `admin` | 4 | System Admin, same as owner but cannot transfer ownership |
| `dev_user` | 2 | Developer, can operate resources but cannot manage members |
| `viewer` | 1 | Read-only access |

> **Assignable Roles** (via API assign): `admin`, `dev_user`, `viewer`. (`owner` must be handled via assign_owner/transfer_owner specific APIs).

#### Resource Roles (High → Low)

| Role | Priority | Description |
|------|----------|-------------|
| `owner` | 5 | Resource Owner |
| `admin` | 4 | Admin |
| `editor` | 3 | Editor |
| `viewer` | 1 | Read-only |

### 2.3 User Types (`user_type`)

| Type | Description |
|------|-------------|
| `member` | Regular individual user (default) |
| `org` | Organizational unit (used for Org Permission Inheritance) |

### 2.4 Resource Types (`resource_type`)

| Type | Description | Parent Resource |
|------|-------------|-----------------|
| `dashboard` | Dashboard resource | None |
| `dashboard_widget` | Child widget within a dashboard | `dashboard` |
| `library_widget` | Shared component library widget | None (managed via namespace) |

---

## 3. Data Models

### 3.1 UserRole (Core Model)

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
    // Audit Fields
    CreatedAt        time.Time  `bson:"created_at"`
    UpdatedAt        time.Time  `bson:"updated_at"`
    DeletedAt        *time.Time `bson:"deleted_at,omitempty"` // Soft delete
    CreatedBy        string     `bson:"created_by,omitempty"`
    UpdatedBy        string     `bson:"updated_by,omitempty"`
    DeletedBy        string     `bson:"deleted_by,omitempty"`
}
```

### 3.2 UserRoleHistory (Audit Log - Append-Only)

```go
type UserRoleHistory struct {
    ID               string    `bson:"_id,omitempty"`
    Operation        string    `bson:"operation"`   // Operation Type
    CallerID         string    `bson:"caller_id"`
    Scope            string    `bson:"scope"`
    Namespace        string    `bson:"namespace,omitempty"`
    ResourceID       string    `bson:"resource_id,omitempty"`
    ResourceType     string    `bson:"resource_type,omitempty"`
    ParentResourceID string    `bson:"parent_resource_id,omitempty"`
    UserID           string    `bson:"user_id,omitempty"`    // Single Operation
    UserIDs          []string  `bson:"user_ids,omitempty"`   // Batch Operation
    UserType         string    `bson:"user_type,omitempty"`
    Role             string    `bson:"role,omitempty"`
    NewOwnerID       string    `bson:"new_owner_id,omitempty"`
    ChildResourceIDs []string  `bson:"child_resource_ids,omitempty"`
    CreatedAt        time.Time `bson:"created_at"`
}
```

**Valid Operations**: `assign_owner`, `transfer_owner`, `assign_user_role`, `assign_user_roles_batch`, `delete_user_role`, `delete_resource`

### 3.3 OrgUser (Organizational User Data)

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

> The [OrgIDs()](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/org_user_repository.go#22-42) method returns a slice of all non-empty field values, used to query roles where `user_type=org`.

### 3.4 MongoDB Index Design

#### `user_roles` Collection
1. **Unique Index** `uniq_user_per_namespace_scope`: [(user_id, user_type, scope, namespace)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129) UNIQUE
2. **Partial Unique Index** `unique_system_owner_v2`: [(scope, namespace)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129) UNIQUE WHERE `scope=system AND role=owner AND deleted_at=nil`

#### `user_resource_roles` Collection
1. **Unique Index** `uniq_user_per_resource_scope`: [(user_id, user_type, scope, resource_type, resource_id)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129) UNIQUE
2. **Partial Unique Index** `unique_resource_owner`: [(scope, resource_id, resource_type)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129) UNIQUE WHERE `scope=resource AND role=owner AND deleted_at=nil`

#### `user_role_history` Collection
1. `idx_system_scope_query`: [(scope, namespace, created_at DESC)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129)
2. `idx_resource_scope_query`: [(scope, resource_id, resource_type, created_at DESC)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129)
3. `idx_created_at`: [(created_at DESC)](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go#28-129)

---

## 4. Policy Engine

### 4.1 Design Philosophy

Permissions are driven by **embedded JSON policy files** rather than hardcoded logic. This enables declarative permission management. The JSON files are embedded into the binary at compile time via `embed.FS`.

### 4.2 CheckScope Types

| CheckScope | Description | Parameter Requirements |
|------------|-------------|------------------------|
| `none` | No permission check needed | None |
| `system` | Check System roles | `namespace` |
| `resource` | Check Resource roles | `resource_id`, `resource_type` |
| `parent_resource` | Check Parent Resource roles | `parent_resource_id` |
| `self_roles` | Check if caller's own role has permission | Evaluated based on retrieved roles |
| `global` | Check global system roles (not restricted by namespace) | None |

### 4.3 Role-Permission Mappings

#### System Roles ([system_roles.json](file:///c:/Users/wenmo/work/rbac7/docs/seed_org_system_roles.json))

```json
{
    "moderator": [
        "platform.system.create", "platform.system.read", "platform.system.add_owner"
    ],
    "owner": [
        "platform.system.update", "platform.system.read",
        "platform.system.add_member", "platform.system.remove_member",
        "platform.system.get_member", "platform.system.transfer_owner",
        "platform.system.read_log",
        "system.resource.create", "system.resource.read",
        "system.resource.delete", "system.resource.update",
        "system.resource.publish", "resource.library_widget.get_member"
    ],
    "admin": [ ... similar to owner but without transfer_owner ... ],
    "dev_user": [
        "platform.system.read", "system.resource.create", "system.resource.read",
        "system.resource.delete", "system.resource.update", "system.resource.publish"
    ],
    "viewer": [
        "platform.system.read", "system.resource.read"
    ]
}
```

#### Resource Roles ([resource_roles.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/roles/resource_roles.json))

```json
{
    "owner": [
        "resource.dashboard.read", "resource.dashboard.update", "resource.dashboard.delete",
        "resource.dashboard.add_member", "resource.dashboard.remove_member", "resource.dashboard.get_member",
        "resource.dashboard.transfer_owner", "resource.dashboard.add_widget", "resource.dashboard.remove_widget",
        "resource.dashboard.add_widget_viewer", "resource.dashboard.read_log",
        "resource.dashboard_widget.read", "resource.dashboard_widget.get_member",
        "resource.library_widget.read"
    ],
    "admin": [ ... similar to owner without transfer_owner ... ],
    "editor": [
        "resource.dashboard.read", "resource.dashboard.update", "resource.dashboard.add_widget",
        "resource.dashboard.remove_widget", "resource.dashboard.add_widget_viewer",
        "resource.dashboard_widget.read", "resource.dashboard_widget.get_member"
    ],
    "viewer": [
        "resource.dashboard.read", "resource.dashboard_widget.read", "resource.library_widget.read"
    ]
}
```

### 4.4 Entity Operation Policies

Each entity has a separate JSON file defining the permission requirements and API route mappings for its operations.

#### System Entity ([system.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/operations/system.json))

| Operation | Required Permission | CheckScope | API |
|-----------|---------------------|------------|-----|
| `assign_owner` | `platform.system.add_owner` | `global` | POST /user_roles/owner |
| `transfer_owner` | `platform.system.transfer_owner` | `system` (namespace_req) | PUT /user_roles/owner |
| `assign_user_role` | `platform.system.add_member` | `system` (namespace_req) | POST /user_roles |
| `assign_user_roles_batch` | `platform.system.add_member` | `system` (namespace_req) | POST /user_roles/batch |
| `delete_user_role` | `platform.system.remove_member` | `system` (namespace_req) | DELETE /user_roles |
| `get_members` | `platform.system.get_member` | `system` (namespace_req) | GET /user_roles (cond: scope=system) |
| `get_my_roles` | `platform.system.read` | `self_roles` | GET /user_roles/me (cond: scope=system) |
| `read_log` | `platform.system.read_log` | `system` (namespace_req) | GET /user_roles/logs (cond: scope=system) |

#### Dashboard Entity ([dashboard.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/operations/dashboard.json))

| Operation | Required Permission | CheckScope | API |
|-----------|---------------------|------------|-----|
| `assign_owner` | (None) | `none` | POST /user_roles/resources/owner (cond: resource_type=dashboard) |
| `transfer_owner` | `resource.dashboard.transfer_owner` | `resource` | PUT /user_roles/resources/owner |
| `assign_user_role` | `resource.dashboard.add_member` | `resource` | POST /user_roles/resources |
| `assign_user_roles_batch` | `resource.dashboard.add_member` | `resource` | POST /user_roles/resources/batch |
| `delete_user_role` | `resource.dashboard.remove_member` | `resource` | DELETE /user_roles/resources |
| `get_members` | `resource.dashboard.get_member` | `resource` | GET /user_roles (cond: scope=resource) |
| `delete_resource` | `resource.dashboard.delete` | `resource` | PUT /resources/delete |
| `get_dashboard` | `resource.dashboard.read` | `resource` | POST /resources/dashboards |

#### Dashboard Widget Entity ([dashboard_widget.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/operations/dashboard_widget.json))

> `parent_entity: "dashboard"` — All operations enforce checking permissions against the **parent dashboard**.

| Operation | Required Permission | CheckScope |
|-----------|---------------------|------------|
| `assign_viewer` | `resource.dashboard.add_widget_viewer` | `parent_resource` |
| `assign_user_roles_batch` | `resource.dashboard.add_widget_viewer` | `parent_resource` |
| `delete_viewer` | `resource.dashboard.add_widget_viewer` | `parent_resource` |
| `get_members` | `resource.dashboard_widget.get_member` | `parent_resource` |
| `delete_resource` | `resource.dashboard.delete` | `parent_resource` |

**Special Interaction:** If `resource_type=dashboard_widget` and `role=viewer`, the Engine automatically overrides `assign_user_role` to use the `assign_viewer` policy blocks.

#### Library Widget Entity ([library_widget.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/operations/library_widget.json))

| Operation | Required Permission | CheckScope |
|-----------|---------------------|------------|
| `assign_viewer` | `platform.system.add_member` | `system` (namespace_req) |
| `get_members` | `resource.library_widget.get_member`| `system` (namespace_req) |
| `delete_resource` | `system.resource.delete` | `system` (namespace_req) |

### 4.5 CheckPermission API Inheritance Strategy ([check_permission.json](file:///c:/Users/wenmo/work/rbac7/internal/rbac/policy/policies/check_permission.json))

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

| Inheritance Mode | Behavior |
|------------------|----------|
| `none` | Strictly checks the roles explicitly assigned to the resource |
| `parent_if_no_roles` | If no roles assigned to widget → inherits parent permission. If roles exist → strict whitelist check. |
| `public_if_no_roles` | If no roles assigned to widget → public access (everyone can read). If roles exist → strict whitelist check. |

---

## 5. RBAC Middleware (Policy-Driven)

### 5.1 Request Flow

```text
HTTP Request
    │
    ▼
1. Build lookup key: "METHOD:PATH" (e.g. POST:/api/v1/user_roles)
    │
    ▼
2. Find matching APIConfig (can map multiple configs to a single path)
    │
    ▼
3. Extract callerID from `x-user-id` HTTP header (required)
    │
    ▼
4. Parse JSON request body (for POST/PUT/DELETE)
    │
    ▼
5. Use conditions to single out the correct config
   (e.g., separating dashboard from dashboard_widget operations on the same path)
    │
    ▼
6. Validate required parameters (e.g., namespace_required, resource_id_required)
    │
    ▼
7. Build an OperationRequest and pass to `PolicyEngine.CheckOperationPermission()`
    │
    ▼
8. allowed=true → continue (`next(c)`); allowed=false → 403 Forbidden
```

### 5.2 Parameter Extraction Mapping

Parameters defined in `params` maps are auto-extracted:
- `body.namespace` → Extracted from request body JSON
- `query.resource_id` → Extracted from URL query string
- `path.id` → Extracted from URL path params
- `header.x-namespace` → Extracted from HTTP headers

---

## 6. Full API Endpoint Specs

### 6.1 Routing

```text
Base URL: /api/v1

# No RBAC Middleware protection (Open APIs)
POST   /permissions/check           # Single permission check (business logic based)
POST   /permissions/check/batch     # Batch permission check

# Protected by RBAC Middleware
# System Scope
POST   /user_roles/owner            # Assign System Owner (moderator only)
PUT    /user_roles/owner            # Transfer System Owner
POST   /user_roles                  # Assign System Role
POST   /user_roles/batch            # Batch Assign System Roles
DELETE /user_roles                  # Delete System Role
GET    /user_roles/me               # Get My Scope Roles
GET    /user_roles                  # List Members in Scope
GET    /user_roles/logs             # Get Role Audit History

# Resource Scope
POST   /user_roles/resources/owner  # Assign Resource Owner
PUT    /user_roles/resources/owner  # Transfer Resource Owner
POST   /user_roles/resources        # Assign Resource Role
POST   /user_roles/resources/batch  # Batch Assign Resource Roles
DELETE /user_roles/resources        # Remove Resource Member

# Resource Management Integration
PUT    /resources/delete            # Soft Delete Resource (cascading)
POST   /resources/dashboards        # Load Dashboard Roles & Accessible Widgets
```

### 6.2 Authentication Headers

- `x-user-id`: Required header identifying the caller's ID.
- `authentication`: Valid auth token (verification deferred to API Gateway, RBAC simply trusts the header).

---

## 7. Core Business Logic Details

### 7.1 Owner Protection Mechanisms

- **Cannot assign owner via standard API**: Prevents assigning `owner` through standard `/user_roles` APIs. Dedicated `assign_owner` / `transfer_owner` endpoints must be used.
- **Upsert Guard**: MongoDB filters apply `role: {$ne: "owner"}` to prevent overwriting existing ownerships via standard member update requests.
- **Sole Owner Restrictions**: When only one owner remains for a namespace or dashboard, they cannot be deleted or downgraded.
- **Atomic Transfer**: `TransferOwner` uses a MongoDB Transaction to demote the old owner to admin and promote the new user to owner simultaneously.

### 7.2 Dashboard Widget Access Control

**Inheritance Mode** (Widget has no explicitly assigned roles):
- Inherits the `resource.dashboard.read` permission of the parent dashboard.

**Whitelist Mode** (Widget has explicitly assigned roles):
- Switches to a strict whitelist: only users explicitly assigned a role on the widget can access it.

**Validation for Adding Widget Viewers**:
- To be assigned a `viewer` role on a widget, the target user must first possess valid read permission on the parent dashboard.

### 7.3 Cascade Deletions

**When deleting a Dashboard Member**:
- Automatically soft-deletes any explicit widget whitelist roles the user might have under that dashboard ([DeleteUserRolesByParent](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/mongo_common_impl.go#412-433)).

**When soft-deleting a Dashboard Resource**:
- Calling `/resources/delete` supporting `child_resource_ids` bulk-soft-deletes the parent dashboard roles and all specified child widget roles in one operation.

### 7.4 Org Permission Inheritance Flow

"Organizational Roles" work as a fallback logic when user permissions are missing:

```text
1. Check User's Direct Roles (user_type = member)
   └─ If allowed → Return True
2. Lookup Org Attributes in `org_users` collection
   └─ Gets orgIDs: [function_id, division_id, dept_id, sect_id, etc.]
3. Query `user_roles` for `user_type=org` where `user_id` IN orgIDs
4. Identify Maximum Role mapping via Priority (GetMaxRole)
5. Check if derived Org Role has the specific permission
   └─ If allowed → Return True
```

**Note**: Org inheritance is active in [CheckPermission](file:///c:/Users/wenmo/work/rbac7/internal/rbac/service/service_common.go#105-131) APIs but bypasses purely implicit evaluation at the Middleware level.

### 7.5 History Logging (Audit Trails)

All mutating operations automatically write to the `user_role_history` collection:
- Excecuted asynchronously via `go recordHistory(...)` fire-and-forget.
- 5-second context timeout on writes.
- Append-only structure ensures the timeline is immutable.

---

## 8. Repository Interfaces

### 8.1 RBACRepository (18 Methods)

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

> **Note**: The [MongoRepository](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/mongo_common_impl.go#14-20) implements both [RBACRepository](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/repository.go#11-51) and [HistoryRepository](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/history_repository.go#10-18).

---

## 9. Configuration Management

Configurations loaded from OS Environment variables (with defaults):

| Environment Variable | Default | Purpose |
|----------------------|---------|---------|
| `MONGO_URI` | `mongodb://localhost:27017` | Standard Mongo DB connection |
| `PORT` | `8080` | Port for the Echo HTTP server |
| `DB_NAME` | `rbac_db` | Primary database name |
| `COLLECTION_USER_ROLES` | `user_roles` | Collection for System Scope roles |
| `COLLECTION_RESOURCE_ROLES` | `user_resource_roles` | Collection for Resource Scope roles |
| `COLLECTION_ORG_USERS` | `org_users` | Collection mapping users to organizational units |

---

## 10. Request Validation Rules

Each DTO (Data Transfer Object) structurally adheres to `go-playground/validator` rules.
The `.Validate()` method typically enforces:
1. **String Normalization**: `TrimSpace`, `ToUpper` (namespaces), `ToLower` (scopes, resource_types).
2. **Tag Rules**: `required`, `min`, `max`, `oneof`.
3. **Business Rules**: Examples:
    - `AssignSystemUserRoleReq`: `role` must be within `oneof=admin viewer dev_user moderator`.
    - [CheckPermissionReq](file:///c:/Users/wenmo/work/rbac7/internal/rbac/model/check_permission_req.go#5-13): If `scope=resource`, both `resource_id` and `resource_type` are strictly enforced.
    - If `resource_type=dashboard_widget`, `parent_resource_id` must be present.

---

## 11. Error Handling

### Service to HTTP Status Mapping

| Service Error Variables | HTTP Status | Error Detail Code |
|-------------------------|-------------|-------------------|
| `ErrUnauthorized` | 401 | `unauthorized` |
| `ErrForbidden` | 403 | `forbidden` |
| `ErrConflict` | 409 | `conflict` |
| `ErrBadRequest`, `ErrInvalidNamespace` | 400 | `bad_request` |
| Catch All / DB Errors | 500 | `internal_error` |

### Error Response Schema

```json
{
    "error": {
        "code": "forbidden",
        "message": "Permission denied"
    }
}
```

---

## 12. Bootstrap Sequence ([main.go](file:///c:/Users/wenmo/work/rbac7/cmd/server/main.go))

```text
1. util.InitLogger()
2. config.LoadConfig() → Load env variables
3. mongo.Connect() → Connect to MongoDB cluster
4. repository.NewMongoRepository() → Appends system and resource role collections
5. repository.NewMongoOrgUserRepository() → Instantiates the organizational resolver
6. repo.EnsureIndexes() & repo.EnsureHistoryIndexes() → Non-blocking index creation
7. service.NewServiceWithOrg() → Instantiates core Services including PolicyEngine injection
8. handler.NewSystemHandler(svc) → Attach HTTP layer mapped via API specs
9. engine.GetLoader().LoadAPIConfigs() → Caches paths/HTTP methods from policies JSONs
10. router.RegisterRoutes() → Finalizes Echo grouping and injects middleware
11. srv.ListenAndServe() + Graceful Shutdown handler reacting to SIGINT/SIGTERM
```

---

## 13. Testing Architecture

Integration verification relies on mock repositories (`testify` & `mockery` patterns) covering:
- **Middleware**: Direct E2E evaluation against JSON loaded configs.
- **CheckPermissions**: Validations verifying explicit user roles and verifying [Org](file:///c:/Users/wenmo/work/rbac7/internal/rbac/repository/org_user_repository.go#22-42) inherited fallback.
- **Widget Controls**: Validating public fallback vs strict member gating.

---

## 14. Summary of Key Design Decisions

1. **Physical Scope Separation**: Storing System and Resource roles in isolated collections enhances index utilization and reduces logical leaks.
2. **Policy-Driven Permissions**: JSON files acting as ground-truth allow runtime behavioral tweaks without code recompilations.
3. **Implicit vs Explicit Check Fallbacks**: Implementing an overarching rule set (`public_if_no_roles`, `parent_if_no_roles`) drastically reduces DB bloat for uniformly open widgets.
4. **Resilient Ownership**: Code ensures namespaces/dashboards never remain orphaned through logic guarantees (Sole Owner protection, Atomic transfers).
5. **Organizational Fallbacks**: Seamless organizational role blending (evaluating a department's standard role seamlessly behind-the-scenes when explicit user roles fall short).
