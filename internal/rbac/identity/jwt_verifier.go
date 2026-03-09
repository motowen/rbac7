package identity

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"rbac7/internal/rbac/config"
)

type TokenVerifier interface {
	VerifyToken(ctx context.Context, token string) (CallerContext, error)
}

type PublicKeySource interface {
	PublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error)
}

type StaticKeySource struct {
	keys map[string]*rsa.PublicKey
}

func NewStaticKeySource(keys map[string]*rsa.PublicKey) *StaticKeySource {
	cloned := make(map[string]*rsa.PublicKey, len(keys))
	for keyID, key := range keys {
		cloned[keyID] = key
	}
	return &StaticKeySource{keys: cloned}
}

func (s *StaticKeySource) PublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	_ = ctx
	if keyID != "" {
		key, ok := s.keys[keyID]
		if !ok {
			return nil, ErrKeyNotFound
		}
		return key, nil
	}

	if len(s.keys) == 1 {
		for _, key := range s.keys {
			return key, nil
		}
	}

	return nil, ErrKeyNotFound
}

type JWTVerifier struct {
	issuer    string
	audience  string
	jwksURL   string
	keySource PublicKeySource
	now       func() time.Time
}

func NewJWTVerifier(cfg config.JWTConfig, keySource PublicKeySource) *JWTVerifier {
	return &JWTVerifier{
		issuer:    cfg.Issuer,
		audience:  cfg.Audience,
		jwksURL:   cfg.JWKSURL,
		keySource: keySource,
		now:       time.Now,
	}
}

func (v *JWTVerifier) VerifyToken(ctx context.Context, token string) (CallerContext, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return CallerContext{}, ErrInvalidToken
	}

	header, err := decodeTokenSegment(parts[0])
	if err != nil {
		return CallerContext{}, err
	}

	if header.Algorithm != "RS256" {
		return CallerContext{}, ErrUnsupportedSigningAlgorithm
	}

	claims, err := decodeClaims(parts[1])
	if err != nil {
		return CallerContext{}, err
	}

	publicKey, err := v.keySource.PublicKey(ctx, header.KeyID)
	if err != nil {
		return CallerContext{}, err
	}

	if err := verifyRS256(parts[0]+"."+parts[1], parts[2], publicKey); err != nil {
		return CallerContext{}, err
	}

	issuer, _ := stringClaim(claims, "iss")
	if v.issuer != "" && issuer != v.issuer {
		return CallerContext{}, ErrInvalidIssuer
	}

	audience, err := audienceClaim(claims)
	if err != nil {
		return CallerContext{}, err
	}
	if v.audience != "" && !contains(audience, v.audience) {
		return CallerContext{}, ErrInvalidAudience
	}

	caller, err := MapClaimsToCallerContext(claims)
	if err != nil {
		return CallerContext{}, err
	}
	caller.Audience = audience

	if !caller.ExpiresAt.After(v.now().UTC()) {
		return CallerContext{}, ErrTokenExpired
	}

	return caller, nil
}

type tokenHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

func decodeTokenSegment(segment string) (tokenHeader, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return tokenHeader{}, ErrInvalidToken
	}

	var header tokenHeader
	if err := json.Unmarshal(decoded, &header); err != nil {
		return tokenHeader{}, ErrInvalidToken
	}
	return header, nil
}

func decodeClaims(segment string) (map[string]any, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func verifyRS256(signingInput, encodedSignature string, publicKey *rsa.PublicKey) error {
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return ErrInvalidToken
	}

	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature); err != nil {
		return fmt.Errorf("%w: signature verification failed", ErrInvalidToken)
	}

	return nil
}

func audienceClaim(claims map[string]any) ([]string, error) {
	value, ok := claims["aud"]
	if !ok || value == nil {
		return nil, fmt.Errorf("%w: missing aud", ErrInvalidClaims)
	}

	switch typed := value.(type) {
	case string:
		return []string{typed}, nil
	case []string:
		return typed, nil
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: invalid aud", ErrInvalidClaims)
			}
			values = append(values, str)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("%w: invalid aud", ErrInvalidClaims)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
