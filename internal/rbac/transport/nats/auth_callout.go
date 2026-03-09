package nats

import (
	"context"
	"time"
)

func (s *Server) handleAuthCallout(ctx context.Context, payload []byte, started time.Time) ([]byte, error) {
	envelope, err := DecodeRequestEnvelope(payload)
	if err != nil {
		return s.encodeAuthCalloutResponse("", false, "bad_request", time.Time{}, "", started), nil
	}

	caller, err := s.verifier.VerifyToken(ctx, envelope.Token)
	if err != nil || caller.UserID == "" {
		return s.encodeAuthCalloutResponse(envelope.RequestID, false, "unauthorized", time.Time{}, "", started), nil
	}

	return s.encodeAuthCalloutResponse(envelope.RequestID, true, "", caller.ExpiresAt, caller.UserID, started), nil
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
