package tests

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"rbac7/internal/rbac/config"
	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTVerifier(t *testing.T) {
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

	t.Run("valid JWT produces a caller context", func(t *testing.T) {
		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":       "https://issuer.example.com",
			"aud":       []string{"rbac-api"},
			"exp":       time.Now().Add(time.Hour).Unix(),
			"sub":       "subject-123",
			"user_id":   "user-123",
			"user_type": model.UserTypeMember,
			"tenant":    "NS_1",
			"org_ids":   []string{"org_1", "org_2"},
		})

		caller, err := verifier.VerifyToken(context.Background(), token)

		require.NoError(t, err)
		assert.Equal(t, "user-123", caller.UserID)
		assert.Equal(t, model.UserTypeMember, caller.UserType)
		assert.Equal(t, "NS_1", caller.ActiveTenant)
		assert.Equal(t, []string{"org_1", "org_2"}, caller.OrgIDs)
		assert.Equal(t, "subject-123", caller.Subject)
	})

	t.Run("wrong issuer is rejected", func(t *testing.T) {
		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":     "https://wrong-issuer.example.com",
			"aud":     []string{"rbac-api"},
			"exp":     time.Now().Add(time.Hour).Unix(),
			"sub":     "subject-123",
			"user_id": "user-123",
			"tenant":  "NS_1",
		})

		_, err := verifier.VerifyToken(context.Background(), token)

		require.Error(t, err)
		assert.ErrorIs(t, err, identity.ErrInvalidIssuer)
	})

	t.Run("wrong audience is rejected", func(t *testing.T) {
		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":     "https://issuer.example.com",
			"aud":     []string{"different-audience"},
			"exp":     time.Now().Add(time.Hour).Unix(),
			"sub":     "subject-123",
			"user_id": "user-123",
			"tenant":  "NS_1",
		})

		_, err := verifier.VerifyToken(context.Background(), token)

		require.Error(t, err)
		assert.ErrorIs(t, err, identity.ErrInvalidAudience)
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		token := signRS256Token(t, privateKey, "kid-1", map[string]any{
			"iss":     "https://issuer.example.com",
			"aud":     []string{"rbac-api"},
			"exp":     time.Now().Add(-time.Minute).Unix(),
			"sub":     "subject-123",
			"user_id": "user-123",
			"tenant":  "NS_1",
		})

		_, err := verifier.VerifyToken(context.Background(), token)

		require.Error(t, err)
		assert.ErrorIs(t, err, identity.ErrTokenExpired)
	})
}

func signRS256Token(t *testing.T, privateKey *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": keyID,
	})
	require.NoError(t, err)

	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims

	hash := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	require.NoError(t, err)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
