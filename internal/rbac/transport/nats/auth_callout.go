package nats

import (
	"context"
	"errors"
	"time"

	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/util"
)

func (s *Server) handleAuthCallout(ctx context.Context, payload []byte, started time.Time) ([]byte, error) {
	envelope, err := DecodeRequestEnvelope(payload)
	if err != nil {
		response := s.encodeAuthCalloutResponse("", false, "bad_request", time.Time{}, "", started)
		s.logAuthCalloutDecision("", "", "deny", "bad_request", started)
		return response, nil
	}

	caller, err := s.verifier.VerifyToken(ctx, envelope.Token)
	if err != nil {
		reasonCode := authCalloutReason(err)
		response := s.encodeAuthCalloutResponse(envelope.RequestID, false, reasonCode, time.Time{}, "", started)
		s.logAuthCalloutDecision(envelope.RequestID, "", "deny", reasonCode, started)
		return response, nil
	}
	if caller.UserID == "" {
		response := s.encodeAuthCalloutResponse(envelope.RequestID, false, "invalid_claims", time.Time{}, "", started)
		s.logAuthCalloutDecision(envelope.RequestID, "", "deny", "invalid_claims", started)
		return response, nil
	}

	response := s.encodeAuthCalloutResponse(envelope.RequestID, true, "", caller.ExpiresAt, caller.UserID, started)
	s.logAuthCalloutDecision(envelope.RequestID, caller.UserID, "allow", reasonRoleMatch, started)
	return response, nil
}

func (s *Server) encodeAuthCalloutResponse(requestID string, allow bool, denyReason string, expiresAt time.Time, userID string, started time.Time) []byte {
	data := map[string]any{
		"allow":       allow,
		"deny_reason": denyReason,
		"user_id":     userID,
		"pub": map[string]any{
			"allow": publishGrants(),
		},
		"sub": map[string]any{
			"allow": subscribeGrants(s.cfg),
		},
	}
	if !expiresAt.IsZero() {
		data["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}
	if !allow {
		data["pub"] = map[string]any{"allow": []string{}}
		data["sub"] = map[string]any{"allow": []string{}}
	}

	code := CodeOK
	if !allow {
		code = CodeUnauthorized
	}

	payload, _ := EncodeResponseEnvelope(ResponseEnvelope{
		RequestID: requestID,
		Code:      code,
		Data:      data,
		Meta:      ResponseMeta{LatencyMS: time.Since(started).Milliseconds()},
	})
	return payload
}

func authCalloutReason(err error) string {
	switch {
	case errors.Is(err, identity.ErrTokenExpired):
		return "token_expired"
	case errors.Is(err, identity.ErrInvalidClaims):
		return "invalid_claims"
	case errors.Is(err, identity.ErrInvalidIssuer):
		return "invalid_issuer"
	case errors.Is(err, identity.ErrInvalidAudience):
		return "invalid_audience"
	case errors.Is(err, identity.ErrUnsupportedSigningAlgorithm):
		return "unsupported_signing_algorithm"
	case errors.Is(err, identity.ErrKeyNotFound):
		return "signing_key_not_found"
	case errors.Is(err, identity.ErrInvalidToken):
		return "invalid_token"
	default:
		return "unauthorized"
	}
}

func (s *Server) logAuthCalloutDecision(requestID, userID, decision, reasonCode string, started time.Time) {
	util.LogRBACDecision("rbac.nats.auth_callout",
		"request_id", requestID,
		"user_id", userID,
		"subject", SubjectAuthCallout,
		"decision", decision,
		"reason_code", reasonCode,
		"latency_ms", time.Since(started).Milliseconds(),
	)
}
