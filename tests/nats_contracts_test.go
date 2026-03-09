package tests

import (
	"encoding/json"
	"testing"

	"rbac7/internal/rbac/service"
	rbacnats "rbac7/internal/rbac/transport/nats"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNATSContracts(t *testing.T) {
	t.Run("stable subject names", func(t *testing.T) {
		assert.Equal(t, "rbac.check", rbacnats.SubjectCheck)
		assert.Equal(t, "rbac.check.batch", rbacnats.SubjectCheckBatch)
		assert.Equal(t, "rbac.roles.me", rbacnats.SubjectRolesMe)
		assert.Equal(t, "rbac.auth.callout", rbacnats.SubjectAuthCallout)
	})

	t.Run("request envelope decoding", func(t *testing.T) {
		body := []byte(`{"request_id":"req-123","token":"jwt-token","data":{"permission":"resource.dashboard.read"}}`)

		envelope, err := rbacnats.DecodeRequestEnvelope(body)

		require.NoError(t, err)
		assert.Equal(t, "req-123", envelope.RequestID)
		assert.Equal(t, "jwt-token", envelope.Token)
		assert.JSONEq(t, `{"permission":"resource.dashboard.read"}`, string(envelope.Data))
	})

	t.Run("response envelope encoding", func(t *testing.T) {
		payload, err := rbacnats.EncodeResponseEnvelope(rbacnats.ResponseEnvelope{
			RequestID: "req-123",
			Code:      rbacnats.CodeOK,
			Message:   "",
			Data: map[string]any{
				"allowed": true,
			},
			Meta: rbacnats.ResponseMeta{LatencyMS: 3},
		})

		require.NoError(t, err)

		var got map[string]any
		err = json.Unmarshal(payload, &got)
		require.NoError(t, err)
		assert.Equal(t, "req-123", got["request_id"])
		assert.Equal(t, string(rbacnats.CodeOK), got["code"])
		assert.Equal(t, true, got["data"].(map[string]any)["allowed"])
		assert.Equal(t, float64(3), got["meta"].(map[string]any)["latency_ms"])
	})

	t.Run("error code mapping", func(t *testing.T) {
		assert.Equal(t, rbacnats.CodeUnauthorized, rbacnats.MapErrorCode(service.ErrUnauthorized))
		assert.Equal(t, rbacnats.CodeForbidden, rbacnats.MapErrorCode(service.ErrForbidden))
		assert.Equal(t, rbacnats.CodeBadRequest, rbacnats.MapErrorCode(service.ErrBadRequest))
		assert.Equal(t, rbacnats.CodeInternalError, rbacnats.MapErrorCode(assert.AnError))
	})
}
