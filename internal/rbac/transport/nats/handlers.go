package nats

import (
	"context"
	"encoding/json"
	"time"

	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/util"
)

const (
	maxBatchResourceIDs    = 100
	maxRequestDataBytes    = 64 * 1024
	reasonBatchTooLarge    = "batch_too_large"
	reasonPayloadTooLarge  = "payload_too_large"
	reasonPermissionDenied = "permission_denied"
	reasonRoleMatch        = "role_match"
	reasonInvalidRequest   = "invalid_request"
)

func (s *Server) handleCheck(ctx context.Context, envelope RequestEnvelope, started time.Time) ([]byte, error) {
	if len(envelope.Data) > maxRequestDataBytes {
		response := s.encodeErrorResponseWithData(envelope.RequestID, CodeBadRequest, "request payload too large", map[string]any{"reason_code": reasonPayloadTooLarge}, started)
		s.logDecision("rbac.check", envelope.RequestID, "", "deny", reasonPayloadTooLarge, started)
		return response, nil
	}

	var req model.CheckPermissionReq
	if err := json.Unmarshal(envelope.Data, &req); err != nil {
		response := s.encodeErrorResponseWithData(envelope.RequestID, CodeBadRequest, "invalid request body", map[string]any{"reason_code": reasonInvalidRequest}, started)
		s.logDecision("rbac.check", envelope.RequestID, "", "deny", reasonInvalidRequest, started)
		return response, nil
	}
	if err := req.Validate(); err != nil {
		response := s.encodeErrorResponseWithData(envelope.RequestID, CodeBadRequest, err.Error(), map[string]any{"reason_code": reasonInvalidRequest}, started)
		s.logDecision("rbac.check", envelope.RequestID, "", "deny", reasonInvalidRequest, started)
		return response, nil
	}

	caller, _ := identity.CallerFromContext(ctx)
	allowed, err := s.service.CheckPermission(ctx, "", req)
	if err != nil {
		response := s.encodeServiceError(envelope.RequestID, err, started)
		s.logDecision("rbac.check", envelope.RequestID, caller.UserID, "error", string(MapErrorCode(err)), started)
		return response, nil
	}

	reasonCode := reasonRoleMatch
	decision := "allow"
	if !allowed {
		reasonCode = reasonPermissionDenied
		decision = "deny"
	}

	response, err := s.encodeSuccessResponse(envelope.RequestID, map[string]any{
		"allowed":     allowed,
		"reason_code": reasonCode,
	}, started)
	if err == nil {
		s.logPermissionDecision(envelope.RequestID, caller.UserID, req, decision, reasonCode, started)
	}
	return response, err
}

func (s *Server) handleCheckBatch(ctx context.Context, envelope RequestEnvelope, started time.Time) ([]byte, error) {
	if len(envelope.Data) > maxRequestDataBytes {
		response := s.encodeErrorResponseWithData(envelope.RequestID, CodeBadRequest, "request payload too large", map[string]any{"reason_code": reasonPayloadTooLarge}, started)
		s.logDecision("rbac.check.batch", envelope.RequestID, "", "deny", reasonPayloadTooLarge, started)
		return response, nil
	}

	var req model.BatchCheckPermissionReq
	if err := json.Unmarshal(envelope.Data, &req); err != nil {
		response := s.encodeErrorResponseWithData(envelope.RequestID, CodeBadRequest, "invalid request body", map[string]any{"reason_code": reasonInvalidRequest}, started)
		s.logDecision("rbac.check.batch", envelope.RequestID, "", "deny", reasonInvalidRequest, started)
		return response, nil
	}
	if len(req.ResourceIDs) > maxBatchResourceIDs {
		response := s.encodeErrorResponseWithData(envelope.RequestID, CodeBadRequest, "batch request too large", map[string]any{"reason_code": reasonBatchTooLarge}, started)
		s.logDecision("rbac.check.batch", envelope.RequestID, "", "deny", reasonBatchTooLarge, started)
		return response, nil
	}
	if err := req.Validate(); err != nil {
		response := s.encodeErrorResponseWithData(envelope.RequestID, CodeBadRequest, err.Error(), map[string]any{"reason_code": reasonInvalidRequest}, started)
		s.logDecision("rbac.check.batch", envelope.RequestID, "", "deny", reasonInvalidRequest, started)
		return response, nil
	}

	caller, _ := identity.CallerFromContext(ctx)
	results, err := s.service.BatchCheckPermission(ctx, "", req)
	if err != nil {
		response := s.encodeServiceError(envelope.RequestID, err, started)
		s.logDecision("rbac.check.batch", envelope.RequestID, caller.UserID, "error", string(MapErrorCode(err)), started)
		return response, nil
	}

	response, err := s.encodeSuccessResponse(envelope.RequestID, map[string]any{"results": results}, started)
	if err == nil {
		s.logDecision("rbac.check.batch", envelope.RequestID, caller.UserID, "allow", reasonRoleMatch, started)
	}
	return response, err
}

func (s *Server) handleRolesMe(ctx context.Context, envelope RequestEnvelope, started time.Time) ([]byte, error) {
	if len(envelope.Data) > maxRequestDataBytes {
		response := s.encodeErrorResponseWithData(envelope.RequestID, CodeBadRequest, "request payload too large", map[string]any{"reason_code": reasonPayloadTooLarge}, started)
		s.logDecision("rbac.roles.me", envelope.RequestID, "", "deny", reasonPayloadTooLarge, started)
		return response, nil
	}

	var req model.GetUserRolesMeReq
	if err := json.Unmarshal(envelope.Data, &req); err != nil {
		response := s.encodeErrorResponseWithData(envelope.RequestID, CodeBadRequest, "invalid request body", map[string]any{"reason_code": reasonInvalidRequest}, started)
		s.logDecision("rbac.roles.me", envelope.RequestID, "", "deny", reasonInvalidRequest, started)
		return response, nil
	}
	if err := req.Validate(); err != nil {
		response := s.encodeErrorResponseWithData(envelope.RequestID, CodeBadRequest, err.Error(), map[string]any{"reason_code": reasonInvalidRequest}, started)
		s.logDecision("rbac.roles.me", envelope.RequestID, "", "deny", reasonInvalidRequest, started)
		return response, nil
	}

	caller, _ := identity.CallerFromContext(ctx)
	roles, err := s.service.GetUserRolesMe(ctx, "", req)
	if err != nil {
		response := s.encodeServiceError(envelope.RequestID, err, started)
		s.logDecision("rbac.roles.me", envelope.RequestID, caller.UserID, "error", string(MapErrorCode(err)), started)
		return response, nil
	}

	response, err := s.encodeSuccessResponse(envelope.RequestID, map[string]any{"roles": roles}, started)
	if err == nil {
		s.logDecision("rbac.roles.me", envelope.RequestID, caller.UserID, "allow", reasonRoleMatch, started)
	}
	return response, err
}

func (s *Server) encodeSuccessResponse(requestID string, data any, started time.Time) ([]byte, error) {
	return EncodeResponseEnvelope(ResponseEnvelope{
		RequestID: requestID,
		Code:      CodeOK,
		Data:      data,
		Meta:      ResponseMeta{LatencyMS: time.Since(started).Milliseconds()},
	})
}

func (s *Server) encodeServiceError(requestID string, err error, started time.Time) []byte {
	payload, _ := EncodeResponseEnvelope(ResponseEnvelope{
		RequestID: requestID,
		Code:      MapErrorCode(err),
		Message:   err.Error(),
		Meta:      ResponseMeta{LatencyMS: time.Since(started).Milliseconds()},
	})
	return payload
}

func (s *Server) encodeErrorResponse(requestID string, code Code, message string, started time.Time) []byte {
	return s.encodeErrorResponseWithData(requestID, code, message, nil, started)
}

func (s *Server) encodeErrorResponseWithData(requestID string, code Code, message string, data any, started time.Time) []byte {
	payload, _ := EncodeResponseEnvelope(ResponseEnvelope{
		RequestID: requestID,
		Code:      code,
		Message:   message,
		Data:      data,
		Meta:      ResponseMeta{LatencyMS: time.Since(started).Milliseconds()},
	})
	return payload
}

func (s *Server) logPermissionDecision(requestID, userID string, req model.CheckPermissionReq, decision, reasonCode string, started time.Time) {
	util.LogRBACDecision("rbac.nats.decision",
		"request_id", requestID,
		"user_id", userID,
		"subject", "rbac.check",
		"permission", req.Permission,
		"scope", req.Scope,
		"namespace", req.Namespace,
		"resource_id", req.ResourceID,
		"resource_type", req.ResourceType,
		"decision", decision,
		"reason_code", reasonCode,
		"latency_ms", time.Since(started).Milliseconds(),
	)
}

func (s *Server) logDecision(subject, requestID, userID, decision, reasonCode string, started time.Time) {
	util.LogRBACDecision("rbac.nats.decision",
		"request_id", requestID,
		"user_id", userID,
		"subject", subject,
		"decision", decision,
		"reason_code", reasonCode,
		"latency_ms", time.Since(started).Milliseconds(),
	)
}
