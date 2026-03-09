package nats

import (
	"context"
	"encoding/json"
	"time"

	"rbac7/internal/rbac/model"
)

func (s *Server) handleCheck(ctx context.Context, envelope RequestEnvelope, started time.Time) ([]byte, error) {
	var req model.CheckPermissionReq
	if err := json.Unmarshal(envelope.Data, &req); err != nil {
		return s.encodeErrorResponse(envelope.RequestID, CodeBadRequest, "invalid request body", started), nil
	}
	if err := req.Validate(); err != nil {
		return s.encodeErrorResponse(envelope.RequestID, CodeBadRequest, err.Error(), started), nil
	}

	allowed, err := s.service.CheckPermission(ctx, "", req)
	if err != nil {
		return s.encodeServiceError(envelope.RequestID, err, started), nil
	}

	return s.encodeSuccessResponse(envelope.RequestID, map[string]any{"allowed": allowed}, started)
}

func (s *Server) handleCheckBatch(ctx context.Context, envelope RequestEnvelope, started time.Time) ([]byte, error) {
	var req model.BatchCheckPermissionReq
	if err := json.Unmarshal(envelope.Data, &req); err != nil {
		return s.encodeErrorResponse(envelope.RequestID, CodeBadRequest, "invalid request body", started), nil
	}
	if err := req.Validate(); err != nil {
		return s.encodeErrorResponse(envelope.RequestID, CodeBadRequest, err.Error(), started), nil
	}

	results, err := s.service.BatchCheckPermission(ctx, "", req)
	if err != nil {
		return s.encodeServiceError(envelope.RequestID, err, started), nil
	}

	return s.encodeSuccessResponse(envelope.RequestID, map[string]any{"results": results}, started)
}

func (s *Server) handleRolesMe(ctx context.Context, envelope RequestEnvelope, started time.Time) ([]byte, error) {
	var req model.GetUserRolesMeReq
	if err := json.Unmarshal(envelope.Data, &req); err != nil {
		return s.encodeErrorResponse(envelope.RequestID, CodeBadRequest, "invalid request body", started), nil
	}
	if err := req.Validate(); err != nil {
		return s.encodeErrorResponse(envelope.RequestID, CodeBadRequest, err.Error(), started), nil
	}

	roles, err := s.service.GetUserRolesMe(ctx, "", req)
	if err != nil {
		return s.encodeServiceError(envelope.RequestID, err, started), nil
	}

	return s.encodeSuccessResponse(envelope.RequestID, map[string]any{"roles": roles}, started)
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
	payload, _ := EncodeResponseEnvelope(ResponseEnvelope{
		RequestID: requestID,
		Code:      code,
		Message:   message,
		Meta:      ResponseMeta{LatencyMS: time.Since(started).Milliseconds()},
	})
	return payload
}
