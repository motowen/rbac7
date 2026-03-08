package natshandler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"rbac7/internal/rbac/config"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
	"rbac7/internal/rbac/util"

	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/synadia-io/callout.go"
)

// AuthCalloutService wraps the callout library with RBAC integration.
// It handles NATS Auth Callout requests by:
// 1. Extracting user identity from the connection's token (JWT)
// 2. Querying the user's RBAC roles
// 3. Mapping roles to coarse-grained NATS subject permissions
// 4. Signing and returning a UserClaims JWT
type AuthCalloutService struct {
	svc        service.RBACService
	accountKP  nkeys.KeyPair
	calloutSvc *callout.AuthorizationService
}

// NewAuthCalloutService creates and starts the Auth Callout service.
// It connects to NATS using the auth user credentials from config,
// then starts listening for auth callout requests on $SYS.REQ.USER.AUTH.
func NewAuthCalloutService(cfg *config.Config, rbacSvc service.RBACService, nc *nats.Conn) (*AuthCalloutService, error) {
	logger := util.GetLogger()

	// Parse account signing key
	accountKP, err := nkeys.FromSeed([]byte(cfg.NATSAccountSeed))
	if err != nil {
		return nil, fmt.Errorf("failed to parse NATS_ACCOUNT_SEED: %w", err)
	}

	acs := &AuthCalloutService{
		svc:       rbacSvc,
		accountKP: accountKP,
	}

	// Build callout options
	opts := []callout.Option{
		callout.Name("rbac-auth-callout"),
		callout.Authorizer(acs.authorizer),
		callout.ResponseSignerKey(accountKP),
		callout.ErrCallback(func(err error) {
			logger.Error("Auth callout error", "error", err)
		}),
	}

	// Add encryption key if configured
	if cfg.NATSEncryptionKey != "" {
		xkp, err := nkeys.FromSeed([]byte(cfg.NATSEncryptionKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse NATS_ENCRYPTION_KEY: %w", err)
		}
		opts = append(opts, callout.EncryptionKey(xkp))
	}

	// Create the callout service
	calloutSvc, err := callout.NewAuthorizationService(nc, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth callout service: %w", err)
	}
	acs.calloutSvc = calloutSvc

	logger.Info("NATS Auth Callout service started")
	return acs, nil
}

// Stop gracefully shuts down the Auth Callout service.
func (acs *AuthCalloutService) Stop() error {
	if acs.calloutSvc != nil {
		return acs.calloutSvc.Stop()
	}
	return nil
}

// authorizer is the AuthorizerFn callback for the callout library.
// It extracts user identity, queries RBAC roles, and generates a UserClaims JWT
// with coarse-grained NATS subject permissions.
func (acs *AuthCalloutService) authorizer(req *natsjwt.AuthorizationRequest) (string, error) {
	logger := util.GetLogger()

	// 1. Extract user identity from the connection token
	// FE sends a JWT token (or plain userID) in the connect options' Token field
	userID := ExtractUserIDFromToken(req.ConnectOptions.Token)
	if userID == "" {
		// Also try username as fallback
		userID = req.ConnectOptions.Username
	}
	if userID == "" {
		logger.Warn("Auth callout: no user identity found, aborting request")
		return "", callout.ErrAbortRequest
	}

	logger.Info("Auth callout: processing authorization", "user_id", userID)

	// 2. Query user's roles (all scopes)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	roles, err := acs.svc.GetUserRolesMe(ctx, userID, model.GetUserRolesMeReq{})
	if err != nil {
		// If roles can't be fetched, still allow basic access (permissions.check only)
		logger.Warn("Auth callout: failed to fetch user roles, granting minimal access",
			"user_id", userID, "error", err)
		roles = nil
	}

	// 3. Build UserClaims
	uc := natsjwt.NewUserClaims(req.UserNkey)
	uc.Audience = "$G" // Global account
	uc.Expires = time.Now().Add(1 * time.Hour).Unix()
	uc.Name = userID

	// 4. Map RBAC roles to NATS pub/sub permissions (coarse-grained)
	natsPerms := MapRolesToNATSPermissions(roles)
	uc.Pub = natsPerms.Pub
	uc.Sub = natsPerms.Sub

	// 5. Encode and return the JWT
	token, err := uc.Encode(acs.accountKP)
	if err != nil {
		return "", fmt.Errorf("failed to encode user JWT: %w", err)
	}

	logger.Info("Auth callout: authorized user",
		"user_id", userID,
		"roles_count", len(roles),
		"pub_allow", len(uc.Pub.Allow),
	)

	return token, nil
}

// ExtractUserIDFromToken extracts the user ID from the connection token.
// Supports:
// - Plain userID string: returned as-is
// - JWT token (3 dot-separated base64 parts): extracts "sub" from the payload
func ExtractUserIDFromToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}

	// Check if it looks like a JWT (has 3 dot-separated parts)
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		return decodeJWTSubject(parts[1])
	}

	// Plain user ID string
	return token
}

// decodeJWTSubject decodes the JWT payload (base64url) and extracts the "sub" field.
func decodeJWTSubject(payload string) string {
	// Base64url decode
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}

	// Parse JSON to extract "sub" field
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		return ""
	}

	return claims.Subject
}
