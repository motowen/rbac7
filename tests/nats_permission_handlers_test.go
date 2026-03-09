package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"rbac7/internal/rbac/config"
	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
	rbacnats "rbac7/internal/rbac/transport/nats"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNATSPermissionHandlers(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	verifier := identity.NewJWTVerifier(
		config.JWTConfig{
			Issuer:   "https://issuer.example.com",
			Audience: "rbac-api",
			JWKSURL:  "https://issuer.example.com/.well-known/jwks.json",
		},
		identity.NewStaticKeySource(map[string]*rsa.PublicKey{
			"kid-1": &privateKey.PublicKey,
		}),
	)

	token := signRS256Token(t, privateKey, "kid-1", map[string]any{
		"iss":       "https://issuer.example.com",
		"aud":       []string{"rbac-api"},
		"exp":       time.Now().Add(time.Hour).Unix(),
		"sub":       "subject-123",
		"user_id":   "jwt-user",
		"user_type": model.UserTypeMember,
		"tenant":    "NS_1",
	})

	t.Run("rbac.check allows a known permission", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)
		mockRepo.On("HasAnySystemRole", mock.Anything, "jwt-user", "NS_1", mock.Anything).Return(true, nil)

		server, err := rbacnats.NewServer(config.NATSConfig{URL: "nats://127.0.0.1:4222"}, svc, verifier)
		require.NoError(t, err)

		payload := mustEncodeRequestEnvelope(t, "req-check", token, map[string]any{
			"permission": model.PermPlatformSystemRead,
			"scope":      model.ScopeSystem,
			"namespace":  "NS_1",
		})
		responseBytes, err := server.HandleRequest(context.Background(), rbacnats.SubjectCheck, payload)
		require.NoError(t, err)

		response := decodeResponseEnvelope(t, responseBytes)
		assert.Equal(t, string(rbacnats.CodeOK), string(response.Code))
		assert.Equal(t, true, response.Data.(map[string]any)["allowed"])
	})

	t.Run("rbac.check rejects invalid request bodies", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)
		server, err := rbacnats.NewServer(config.NATSConfig{URL: "nats://127.0.0.1:4222"}, svc, verifier)
		require.NoError(t, err)

		payload := mustEncodeRequestEnvelope(t, "req-invalid", token, map[string]any{
			"scope":     model.ScopeSystem,
			"namespace": "NS_1",
		})
		responseBytes, err := server.HandleRequest(context.Background(), rbacnats.SubjectCheck, payload)
		require.NoError(t, err)

		response := decodeResponseEnvelope(t, responseBytes)
		assert.Equal(t, string(rbacnats.CodeBadRequest), string(response.Code))
	})

	t.Run("rbac.check.batch returns a result map", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "jwt-user", "d1", "dashboard", mock.Anything).Return(true, nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "jwt-user", "d2", "dashboard", mock.Anything).Return(false, nil)

		server, err := rbacnats.NewServer(config.NATSConfig{URL: "nats://127.0.0.1:4222"}, svc, verifier)
		require.NoError(t, err)

		payload := mustEncodeRequestEnvelope(t, "req-batch", token, map[string]any{
			"permission":    model.PermResourceDashboardRead,
			"resource_type": model.ResourceTypeDashboard,
			"resource_ids":  []string{"d1", "d2"},
		})
		responseBytes, err := server.HandleRequest(context.Background(), rbacnats.SubjectCheckBatch, payload)
		require.NoError(t, err)

		response := decodeResponseEnvelope(t, responseBytes)
		assert.Equal(t, string(rbacnats.CodeOK), string(response.Code))
		results := response.Data.(map[string]any)["results"].(map[string]any)
		assert.Equal(t, true, results["d1"])
		assert.Equal(t, false, results["d2"])
	})

	t.Run("rbac.roles.me returns only the caller roles", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)
		mockRepo.On("FindUserRoles", mock.Anything, model.UserRoleFilter{
			UserID: "jwt-user",
			Scope:  model.ScopeSystem,
		}).Return([]*model.UserRole{{
			UserID:    "jwt-user",
			Role:      model.RoleSystemAdmin,
			Scope:     model.ScopeSystem,
			Namespace: "NS_1",
			UserType:  model.UserTypeMember,
		}}, nil)

		server, err := rbacnats.NewServer(config.NATSConfig{URL: "nats://127.0.0.1:4222"}, svc, verifier)
		require.NoError(t, err)

		payload := mustEncodeRequestEnvelope(t, "req-roles", token, map[string]any{
			"scope": model.ScopeSystem,
		})
		responseBytes, err := server.HandleRequest(context.Background(), rbacnats.SubjectRolesMe, payload)
		require.NoError(t, err)

		response := decodeResponseEnvelope(t, responseBytes)
		assert.Equal(t, string(rbacnats.CodeOK), string(response.Code))
		roles := response.Data.(map[string]any)["roles"].([]any)
		require.Len(t, roles, 1)
		assert.Equal(t, "jwt-user", roles[0].(map[string]any)["UserID"])
	})

	t.Run("server construction accepts NATS config and verifier", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)

		server, err := rbacnats.NewServer(config.NATSConfig{URL: "nats://127.0.0.1:4222"}, svc, verifier)

		require.NoError(t, err)
		assert.NotNil(t, server)
	})
}

func mustEncodeRequestEnvelope(t *testing.T, requestID, token string, data any) []byte {
	t.Helper()
	payload, err := json.Marshal(rbacnats.RequestEnvelope{RequestID: requestID, Token: token, Data: mustMarshalJSON(t, data)})
	require.NoError(t, err)
	return payload
}

func mustMarshalJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(value)
	require.NoError(t, err)
	return payload
}

func decodeResponseEnvelope(t *testing.T, payload []byte) rbacnats.ResponseEnvelope {
	t.Helper()
	var envelope rbacnats.ResponseEnvelope
	err := json.Unmarshal(payload, &envelope)
	require.NoError(t, err)
	return envelope
}
