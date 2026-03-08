package natshandler

import (
	"context"
	"encoding/json"
	"time"

	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/policy"
	"rbac7/internal/rbac/repository"
	"rbac7/internal/rbac/service"
	"rbac7/internal/rbac/util"

	"github.com/nats-io/nats.go"
)

// NATSRequest is the unified NATS message format sent by FE.
type NATSRequest struct {
	CallerID string          `json:"caller_id"`
	Data     json.RawMessage `json:"data"`
}

// NATSResponse is the unified NATS response format.
type NATSResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *NATSError  `json:"error,omitempty"`
}

// NATSError represents an error in a NATS response.
type NATSError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NATSHandler handles NATS request-reply messages, mirroring the HTTP handlers.
type NATSHandler struct {
	svc     service.RBACService
	rbac    *NATSRBACChecker
	conn    *nats.Conn
	subs    []*nats.Subscription
	timeout time.Duration
}

// NewNATSHandler creates a new NATS handler.
func NewNATSHandler(
	conn *nats.Conn,
	svc service.RBACService,
	policyEngine *policy.Engine,
	repo repository.RBACRepository,
) *NATSHandler {
	return &NATSHandler{
		svc:     svc,
		rbac:    NewNATSRBACChecker(policyEngine, repo),
		conn:    conn,
		timeout: 10 * time.Second,
	}
}

// RegisterAll subscribes to all RBAC NATS subjects.
func (h *NATSHandler) RegisterAll() error {
	logger := util.GetLogger()

	subjects := map[string]nats.MsgHandler{
		// Permissions (no RBAC middleware)
		"rbac.permissions.check":       h.handleCheckPermission,
		"rbac.permissions.check.batch": h.handleBatchCheckPermission,

		// System Scope
		"rbac.system.assign_owner":       h.handleAssignSystemOwner,
		"rbac.system.transfer_owner":     h.handleTransferSystemOwner,
		"rbac.system.assign_role":        h.handleAssignSystemUserRole,
		"rbac.system.assign_roles_batch": h.handleAssignSystemUserRoles,
		"rbac.system.delete_role":        h.handleDeleteSystemUserRole,
		"rbac.system.get_my_roles":       h.handleGetUserRolesMe,
		"rbac.system.get_members":        h.handleGetUserRoles,
		"rbac.system.get_logs":           h.handleGetUserRoleHistory,

		// Resource Scope
		"rbac.resource.assign_owner":       h.handleAssignResourceOwner,
		"rbac.resource.transfer_owner":     h.handleTransferResourceOwner,
		"rbac.resource.assign_role":        h.handleAssignResourceUserRole,
		"rbac.resource.assign_roles_batch": h.handleAssignResourceUserRoles,
		"rbac.resource.delete_role":        h.handleDeleteResourceUserRole,
		"rbac.resource.delete":             h.handleSoftDeleteResource,
		"rbac.resource.get_dashboard":      h.handleGetDashboardResource,
	}

	for subject, handler := range subjects {
		sub, err := h.conn.Subscribe(subject, handler)
		if err != nil {
			return err
		}
		h.subs = append(h.subs, sub)
		logger.Info("NATS handler registered", "subject", subject)
	}

	logger.Info("All NATS handlers registered", "count", len(subjects))
	return nil
}

// UnsubscribeAll unsubscribes from all subjects.
func (h *NATSHandler) UnsubscribeAll() {
	for _, sub := range h.subs {
		_ = sub.Unsubscribe()
	}
}

// --- Helper Methods ---

// parseRequest extracts NATSRequest and validates callerID.
func (h *NATSHandler) parseRequest(msg *nats.Msg) (*NATSRequest, error) {
	var req NATSRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// respond sends a response back on the reply subject.
func (h *NATSHandler) respond(msg *nats.Msg, data []byte) {
	if msg.Reply == "" {
		return
	}
	_ = h.conn.Publish(msg.Reply, data)
}

// respondError is a helper to send an error response.
func (h *NATSHandler) respondError(msg *nats.Msg, natsErr *NATSError) {
	h.respond(msg, makeErrorResponse(natsErr))
}

// respondSuccess is a helper to send a success response.
func (h *NATSHandler) respondSuccess(msg *nats.Msg, result interface{}) {
	h.respond(msg, makeSuccessResponse(result))
}

// newCtx creates a context with timeout for handler operations.
func (h *NATSHandler) newCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), h.timeout)
}

// --- Permission Check Handlers (No RBAC Middleware) ---

func (h *NATSHandler) handleCheckPermission(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.CheckPermissionReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	allowed, err := h.svc.CheckPermission(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, model.CheckPermissionResponse{Allowed: allowed})
}

func (h *NATSHandler) handleBatchCheckPermission(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.BatchCheckPermissionReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	results, err := h.svc.BatchCheckPermission(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, model.BatchCheckPermissionResponse{Results: results})
}

// --- System Scope Handlers (With RBAC Check) ---

func (h *NATSHandler) handleAssignSystemOwner(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.AssignSystemOwnerReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check: system.assign_owner
	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID, "system", "assign_owner", req.Namespace, "", "", "", "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	err = h.svc.AssignSystemOwner(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, map[string]string{"status": "success"})
}

func (h *NATSHandler) handleTransferSystemOwner(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.TransferSystemOwnerReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check: system.transfer_owner
	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID, "system", "transfer_owner", req.Namespace, "", "", "", "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	err = h.svc.TransferSystemOwner(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, map[string]string{"status": "success"})
}

func (h *NATSHandler) handleAssignSystemUserRole(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.AssignSystemUserRoleReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check: system.assign_user_role
	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID, "system", "assign_user_role", req.Namespace, "", "", "", "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	err = h.svc.AssignSystemUserRole(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, map[string]string{"status": "success"})
}

func (h *NATSHandler) handleAssignSystemUserRoles(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.AssignSystemUserRolesReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check: system.assign_user_roles_batch
	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID, "system", "assign_user_roles_batch", req.Namespace, "", "", "", "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	result, err := h.svc.AssignSystemUserRoles(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, result)
}

func (h *NATSHandler) handleDeleteSystemUserRole(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.DeleteSystemUserRoleReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check: system.delete_user_role
	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID, "system", "delete_user_role", req.Namespace, "", "", "", "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	err = h.svc.DeleteSystemUserRole(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, map[string]string{"status": "success"})
}

func (h *NATSHandler) handleGetUserRolesMe(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.GetUserRolesMeReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// No explicit RBAC check — GetUserRolesMe does self_roles check internally
	roles, err := h.svc.GetUserRolesMe(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, roles)
}

func (h *NATSHandler) handleGetUserRoles(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.GetUserRolesReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check: system.get_members or dashboard.get_members depends on scope
	entity := "system"
	operation := "get_members"
	if req.Scope == model.ScopeResource {
		entity = req.ResourceType
		if entity == "" {
			entity = "dashboard"
		}
	}
	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID, entity, operation,
		req.Namespace, req.ResourceID, req.ResourceType, req.ParentResourceID, "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	roles, err := h.svc.GetUserRoles(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, roles)
}

func (h *NATSHandler) handleGetUserRoleHistory(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.GetUserRoleHistoryReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check: system/dashboard.read_log
	entity := "system"
	if req.Scope == model.ScopeResource {
		entity = req.ResourceType
		if entity == "" {
			entity = "dashboard"
		}
	}
	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID, entity, "read_log",
		req.Namespace, req.ResourceID, req.ResourceType, "", "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	result, err := h.svc.GetUserRoleHistory(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, result)
}

// --- Resource Scope Handlers (With RBAC Check) ---

func (h *NATSHandler) handleAssignResourceOwner(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.AssignResourceOwnerReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// assign_owner for dashboard has check_scope=none, so skip RBAC
	err = h.svc.AssignResourceOwner(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, map[string]string{"status": "success"})
}

func (h *NATSHandler) handleTransferResourceOwner(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.TransferResourceOwnerReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check: dashboard.transfer_owner
	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID,
		req.ResourceType, "transfer_owner", "", req.ResourceID, req.ResourceType, "", "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	err = h.svc.TransferResourceOwner(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, map[string]string{"status": "success"})
}

func (h *NATSHandler) handleAssignResourceUserRole(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.AssignResourceUserRoleReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// Determine entity and operation (mirrors HTTP middleware condition matching)
	entity := req.ResourceType
	operation := "assign_user_role"
	if req.ResourceType == "dashboard_widget" && req.Role == "viewer" {
		operation = "assign_viewer"
	}

	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID,
		entity, operation, "", req.ResourceID, req.ResourceType, req.ParentResourceID, req.Role)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	err = h.svc.AssignResourceUserRole(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, map[string]string{"status": "success"})
}

func (h *NATSHandler) handleAssignResourceUserRoles(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.AssignResourceUserRolesReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check
	entity := req.ResourceType
	operation := "assign_user_roles_batch"
	if req.ResourceType == "dashboard_widget" {
		operation = "assign_user_roles_batch"
	}

	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID,
		entity, operation, req.Namespace, req.ResourceID, req.ResourceType, req.ParentResourceID, req.Role)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	result, err := h.svc.AssignResourceUserRoles(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, result)
}

func (h *NATSHandler) handleDeleteResourceUserRole(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.DeleteResourceUserRoleReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// Determine entity/operation
	entity := req.ResourceType
	operation := "delete_user_role"
	if req.ResourceType == "dashboard_widget" {
		operation = "delete_viewer"
	}

	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID,
		entity, operation, "", req.ResourceID, req.ResourceType, req.ParentResourceID, "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	err = h.svc.DeleteResourceUserRole(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, map[string]string{"status": "success"})
}

func (h *NATSHandler) handleSoftDeleteResource(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.SoftDeleteResourceReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check: delete_resource
	entity := req.ResourceType
	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID,
		entity, "delete_resource", req.Namespace, req.ResourceID, req.ResourceType, req.ParentResourceID, "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	err = h.svc.SoftDeleteResource(ctx, natsReq.CallerID, &req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, map[string]string{"status": "success"})
}

func (h *NATSHandler) handleGetDashboardResource(msg *nats.Msg) {
	natsReq, err := h.parseRequest(msg)
	if err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid message format"})
		return
	}
	if natsReq.CallerID == "" {
		h.respondError(msg, &NATSError{Code: "unauthorized", Message: "caller_id is required"})
		return
	}

	var req model.GetDashboardResourceReq
	if err := json.Unmarshal(natsReq.Data, &req); err != nil {
		h.respondError(msg, &NATSError{Code: "bad_request", Message: "Invalid data"})
		return
	}
	if err := req.Validate(); err != nil {
		h.respondError(msg, validationNATSError(err))
		return
	}

	ctx, cancel := h.newCtx()
	defer cancel()

	// RBAC check: dashboard.get_dashboard
	allowed, err := h.rbac.CheckOperationPermission(ctx, natsReq.CallerID,
		"dashboard", "get_dashboard", "", req.ResourceID, "dashboard", "", "")
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}
	if !allowed {
		h.respondError(msg, &NATSError{Code: "forbidden", Message: "Permission denied"})
		return
	}

	result, err := h.svc.GetDashboardResource(ctx, natsReq.CallerID, req)
	if err != nil {
		h.respondError(msg, natsError(err))
		return
	}

	h.respondSuccess(msg, result)
}
