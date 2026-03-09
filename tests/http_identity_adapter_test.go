package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"rbac7/internal/rbac/config"
	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestHTTPIdentityAdapter(t *testing.T) {
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
	headers := map[string]string{"Authorization": "Bearer " + token}

	t.Run("permission check handler uses bearer token instead of x-user-id", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		mockRepo.On("HasAnySystemRole", mock.Anything, "jwt-user", "NS_1", mock.Anything).Return(true, nil)

		e := SetupServerWithMiddlewareAndVerifier(mockRepo, nil, verifier)
		rec := PerformRequest(e, http.MethodPost, "/api/v1/permissions/check", map[string]any{
			"permission": model.PermPlatformSystemRead,
			"scope":      model.ScopeSystem,
			"namespace":  "NS_1",
		}, headers)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.JSONEq(t, `{"allowed":true}`, rec.Body.String())
		mockRepo.AssertExpectations(t)
	})

	t.Run("middleware and handler build caller context from bearer token", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
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

		e := SetupServerWithMiddlewareAndVerifier(mockRepo, nil, verifier)
		rec := PerformRequest(e, http.MethodGet, "/api/v1/user_roles/me?scope=system", nil, headers)

		assert.Equal(t, http.StatusOK, rec.Code)

		var roles []model.UserRole
		err := json.Unmarshal(rec.Body.Bytes(), &roles)
		require.NoError(t, err)
		require.Len(t, roles, 1)
		assert.Equal(t, "jwt-user", roles[0].UserID)
		mockRepo.AssertExpectations(t)
	})
}
