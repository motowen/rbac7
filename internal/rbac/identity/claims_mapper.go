package identity

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidToken                = errors.New("invalid token")
	ErrInvalidIssuer               = errors.New("invalid issuer")
	ErrInvalidAudience             = errors.New("invalid audience")
	ErrTokenExpired                = errors.New("token expired")
	ErrInvalidClaims               = errors.New("invalid claims")
	ErrUnsupportedSigningAlgorithm = errors.New("unsupported signing algorithm")
	ErrKeyNotFound                 = errors.New("signing key not found")
)

func MapClaimsToCallerContext(claims map[string]any) (CallerContext, error) {
	userID, _ := stringClaim(claims, "user_id")
	if userID == "" {
		userID, _ = stringClaim(claims, "sub")
	}
	if userID == "" {
		return CallerContext{}, fmt.Errorf("%w: missing user_id", ErrInvalidClaims)
	}

	subject, _ := stringClaim(claims, "sub")
	userType, _ := stringClaim(claims, "user_type")
	tenant, _ := stringClaim(claims, "tenant")
	orgIDs, err := stringSliceClaim(claims, "org_ids")
	if err != nil {
		return CallerContext{}, err
	}

	expiresAt, err := timeClaim(claims, "exp")
	if err != nil {
		return CallerContext{}, err
	}

	return CallerContext{
		UserID:       userID,
		UserType:     userType,
		ActiveTenant: tenant,
		OrgIDs:       orgIDs,
		Subject:      subject,
		ExpiresAt:    expiresAt,
		RawClaims:    claims,
	}, nil
}

func stringClaim(claims map[string]any, key string) (string, bool) {
	value, ok := claims[key]
	if !ok || value == nil {
		return "", false
	}

	s, ok := value.(string)
	return s, ok
}

func stringSliceClaim(claims map[string]any, key string) ([]string, error) {
	value, ok := claims[key]
	if !ok || value == nil {
		return nil, nil
	}

	switch typed := value.(type) {
	case []string:
		return typed, nil
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: %s must be a string array", ErrInvalidClaims, key)
			}
			values = append(values, str)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("%w: %s must be a string array", ErrInvalidClaims, key)
	}
}

func timeClaim(claims map[string]any, key string) (time.Time, error) {
	value, ok := claims[key]
	if !ok || value == nil {
		return time.Time{}, fmt.Errorf("%w: missing %s", ErrInvalidClaims, key)
	}

	switch typed := value.(type) {
	case float64:
		return time.Unix(int64(typed), 0).UTC(), nil
	case int64:
		return time.Unix(typed, 0).UTC(), nil
	case jsonNumber:
		seconds, err := typed.Int64()
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: invalid %s", ErrInvalidClaims, key)
		}
		return time.Unix(seconds, 0).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("%w: invalid %s", ErrInvalidClaims, key)
	}
}

type jsonNumber interface {
	Int64() (int64, error)
}
