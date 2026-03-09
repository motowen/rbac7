package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"rbac7/internal/rbac/config"
	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/service"
	rbacnats "rbac7/internal/rbac/transport/nats"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNATSAuthCallout(t *testing.T) {
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

	server, err := rbacnats.NewServer(config.NATSConfig{
		URL:                       "nats://127.0.0.1:4222",
		AppRequestSubjectPrefixes: []string{"app.rpc.>"},
	}, service.NewService(new(MockRBACRepository), new(MockRBACRepository)), verifier)
	require.NoError(t, err)

	t.Run("valid JWT receives allow with expected subjects", func(t *testing.T) {
		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":     "https://issuer.example.com",
			"aud":     []string{"rbac-api"},
			"exp":     time.Now().Add(time.Hour).Unix(),
			"sub":     "subject-123",
			"user_id": "jwt-user",
		})

		payload, err := server.HandleRequest(context.Background(), rbacnats.SubjectAuthCallout, mustEncodeRequestEnvelope(t, "req-callout", token, map[string]any{}))
		require.NoError(t, err)
		response := decodeResponseEnvelope(t, payload)

		assert.Equal(t, string(rbacnats.CodeOK), string(response.Code))
		assert.Equal(t, true, response.Data.(map[string]any)["allow"])
		pub := response.Data.(map[string]any)["pub"].(map[string]any)["allow"].([]any)
		sub := response.Data.(map[string]any)["sub"].(map[string]any)["allow"].([]any)
		assert.Contains(t, pub, "_INBOX.>")
		assert.Contains(t, sub, rbacnats.SubjectCheck)
		assert.Contains(t, sub, rbacnats.SubjectCheckBatch)
		assert.Contains(t, sub, rbacnats.SubjectRolesMe)
	})

	t.Run("expired JWT is denied", func(t *testing.T) {
		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":     "https://issuer.example.com",
			"aud":     []string{"rbac-api"},
			"exp":     time.Now().Add(-time.Minute).Unix(),
			"sub":     "subject-123",
			"user_id": "jwt-user",
		})

		payload, err := server.HandleRequest(context.Background(), rbacnats.SubjectAuthCallout, mustEncodeRequestEnvelope(t, "req-expired", token, map[string]any{}))
		require.NoError(t, err)
		response := decodeResponseEnvelope(t, payload)
		assert.Equal(t, string(rbacnats.CodeUnauthorized), string(response.Code))
		assert.Equal(t, false, response.Data.(map[string]any)["allow"])
	})

	t.Run("malformed claims are denied", func(t *testing.T) {
		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":     "https://issuer.example.com",
			"aud":     []string{"rbac-api"},
			"exp":     time.Now().Add(time.Hour).Unix(),
			"sub":     "subject-123",
			"user_id": "jwt-user",
			"org_ids": "not-an-array",
		})

		payload, err := server.HandleRequest(context.Background(), rbacnats.SubjectAuthCallout, mustEncodeRequestEnvelope(t, "req-malformed", token, map[string]any{}))
		require.NoError(t, err)
		response := decodeResponseEnvelope(t, payload)
		assert.Equal(t, string(rbacnats.CodeUnauthorized), string(response.Code))
		assert.Equal(t, false, response.Data.(map[string]any)["allow"])
	})

	t.Run("auth callout never returns resource-specific subject grants", func(t *testing.T) {
		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":     "https://issuer.example.com",
			"aud":     []string{"rbac-api"},
			"exp":     time.Now().Add(time.Hour).Unix(),
			"sub":     "subject-123",
			"user_id": "jwt-user",
		})

		payload, err := server.HandleRequest(context.Background(), rbacnats.SubjectAuthCallout, mustEncodeRequestEnvelope(t, "req-grants", token, map[string]any{}))
		require.NoError(t, err)
		response := decodeResponseEnvelope(t, payload)

		pub := response.Data.(map[string]any)["pub"].(map[string]any)["allow"].([]any)
		sub := response.Data.(map[string]any)["sub"].(map[string]any)["allow"].([]any)
		for _, grant := range append(pub, sub...) {
			assert.False(t, strings.Contains(grant.(string), "dashboard"))
			assert.False(t, strings.HasPrefix(grant.(string), ">"))
		}
	})

	t.Run("coarse-grained grants include only configured application request prefixes", func(t *testing.T) {
		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":     "https://issuer.example.com",
			"aud":     []string{"rbac-api"},
			"exp":     time.Now().Add(time.Hour).Unix(),
			"sub":     "subject-123",
			"user_id": "jwt-user",
		})

		payload, err := server.HandleRequest(context.Background(), rbacnats.SubjectAuthCallout, mustEncodeRequestEnvelope(t, "req-prefix", token, map[string]any{}))
		require.NoError(t, err)
		response := decodeResponseEnvelope(t, payload)
		sub := response.Data.(map[string]any)["sub"].(map[string]any)["allow"].([]any)

		assert.Contains(t, sub, "app.rpc.>")
		for _, grant := range sub {
			text := grant.(string)
			if strings.HasPrefix(text, "app.") {
				assert.Equal(t, "app.rpc.>", text)
			}
		}
	})
}

func decodeRawResponseEnvelope(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	var envelope map[string]any
	err := json.Unmarshal(payload, &envelope)
	require.NoError(t, err)
	return envelope
}
