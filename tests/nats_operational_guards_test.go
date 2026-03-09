package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
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

func TestNATSOperationalGuards(t *testing.T) {
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

	t.Run("rbac.check.batch rejects oversized payloads", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)
		server, err := rbacnats.NewServer(config.NATSConfig{URL: "nats://127.0.0.1:4222"}, svc, verifier)
		require.NoError(t, err)

		resourceIDs := make([]string, 101)
		for i := range resourceIDs {
			resourceIDs[i] = fmt.Sprintf("d-%03d", i)
		}

		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":       "https://issuer.example.com",
			"aud":       []string{"rbac-api"},
			"exp":       time.Now().Add(time.Hour).Unix(),
			"sub":       "subject-123",
			"user_id":   "jwt-user",
			"user_type": model.UserTypeMember,
		})

		payload := mustEncodeRequestEnvelope(t, "req-batch-too-large", token, map[string]any{
			"permission":    model.PermResourceDashboardRead,
			"resource_type": model.ResourceTypeDashboard,
			"resource_ids":  resourceIDs,
		})
		responseBytes, err := server.HandleRequest(context.Background(), rbacnats.SubjectCheckBatch, payload)
		require.NoError(t, err)

		response := decodeRawResponseEnvelope(t, responseBytes)
		assert.Equal(t, "req-batch-too-large", response["request_id"])
		assert.Equal(t, string(rbacnats.CodeBadRequest), response["code"])
		require.IsType(t, map[string]any{}, response["data"])
		assert.Equal(t, "batch_too_large", response["data"].(map[string]any)["reason_code"])
	})

	t.Run("request ids are echoed in error responses", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)
		server, err := rbacnats.NewServer(config.NATSConfig{URL: "nats://127.0.0.1:4222"}, svc, verifier)
		require.NoError(t, err)

		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":     "https://issuer.example.com",
			"aud":     []string{"rbac-api"},
			"exp":     time.Now().Add(time.Hour).Unix(),
			"sub":     "subject-123",
			"user_id": "jwt-user",
		})

		payload := mustEncodeRequestEnvelope(t, "req-invalid-body", token, map[string]any{
			"scope": model.ScopeSystem,
		})
		responseBytes, err := server.HandleRequest(context.Background(), rbacnats.SubjectCheck, payload)
		require.NoError(t, err)

		response := decodeRawResponseEnvelope(t, responseBytes)
		assert.Equal(t, "req-invalid-body", response["request_id"])
		assert.Equal(t, string(rbacnats.CodeBadRequest), response["code"])
	})

	t.Run("deny decisions include stable permission reason codes", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)
		mockRepo.On("HasAnySystemRole", mock.Anything, "jwt-user", "NS_1", mock.Anything).Return(false, nil)

		server, err := rbacnats.NewServer(config.NATSConfig{URL: "nats://127.0.0.1:4222"}, svc, verifier)
		require.NoError(t, err)

		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":       "https://issuer.example.com",
			"aud":       []string{"rbac-api"},
			"exp":       time.Now().Add(time.Hour).Unix(),
			"sub":       "subject-123",
			"user_id":   "jwt-user",
			"user_type": model.UserTypeMember,
			"tenant":    "NS_1",
		})

		payload := mustEncodeRequestEnvelope(t, "req-deny-reason", token, map[string]any{
			"permission": model.PermPlatformSystemRead,
			"scope":      model.ScopeSystem,
			"namespace":  "NS_1",
		})
		responseBytes, err := server.HandleRequest(context.Background(), rbacnats.SubjectCheck, payload)
		require.NoError(t, err)

		response := decodeRawResponseEnvelope(t, responseBytes)
		assert.Equal(t, string(rbacnats.CodeOK), response["code"])
		require.IsType(t, map[string]any{}, response["data"])
		assert.Equal(t, false, response["data"].(map[string]any)["allowed"])
		assert.Equal(t, "permission_denied", response["data"].(map[string]any)["reason_code"])
	})

	t.Run("auth callout denies with stable reason codes", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)
		server, err := rbacnats.NewServer(config.NATSConfig{URL: "nats://127.0.0.1:4222"}, svc, verifier)
		require.NoError(t, err)

		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":     "https://issuer.example.com",
			"aud":     []string{"rbac-api"},
			"exp":     time.Now().Add(-time.Minute).Unix(),
			"sub":     "subject-123",
			"user_id": "jwt-user",
		})

		responseBytes, err := server.HandleRequest(context.Background(), rbacnats.SubjectAuthCallout, mustEncodeRequestEnvelope(t, "req-expired-token", token, map[string]any{}))
		require.NoError(t, err)

		response := decodeRawResponseEnvelope(t, responseBytes)
		assert.Equal(t, "req-expired-token", response["request_id"])
		assert.Equal(t, string(rbacnats.CodeUnauthorized), response["code"])
		require.IsType(t, map[string]any{}, response["data"])
		assert.Equal(t, false, response["data"].(map[string]any)["allow"])
		assert.Equal(t, "token_expired", response["data"].(map[string]any)["deny_reason"])
	})
}
