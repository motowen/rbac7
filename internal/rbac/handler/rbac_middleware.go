package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/policy"
	"rbac7/internal/rbac/repository"
	"rbac7/internal/rbac/service"

	"github.com/labstack/echo/v4"
)

// RBACMiddleware handles permission checking based on JSON configuration
type RBACMiddleware struct {
	policyEngine *policy.Engine
	repo         repository.RBACRepository
	apiConfigs   map[string][]*policy.APIConfig // key: "METHOD:PATH"
	verifier     identity.TokenVerifier
}

// NewRBACMiddleware creates a new RBAC middleware instance
func NewRBACMiddleware(engine *policy.Engine, repo repository.RBACRepository, apiConfigs map[string][]*policy.APIConfig) *RBACMiddleware {
	return NewRBACMiddlewareWithVerifier(engine, repo, apiConfigs, nil)
}

func NewRBACMiddlewareWithVerifier(engine *policy.Engine, repo repository.RBACRepository, apiConfigs map[string][]*policy.APIConfig, verifier identity.TokenVerifier) *RBACMiddleware {
	return &RBACMiddleware{
		policyEngine: engine,
		repo:         repo,
		apiConfigs:   apiConfigs,
		verifier:     verifier,
	}
}

// Middleware returns the Echo middleware function
func (m *RBACMiddleware) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := c.Request().Method + ":" + c.Path()

			configs, exists := m.apiConfigs[key]
			log.Printf("Audit:RBACMiddleware. key=%s, configs=%v, exists=%v", key, configs, exists)

			if !exists {
				return c.JSON(http.StatusBadRequest, model.ErrorResponse{
					Error: model.ErrorDetail{Code: "bad_request", Message: "No matching RBAC configuration for this request"},
				})
			}

			callerID, err := m.authenticateRequest(c)
			if err != nil {
				code, body := httpError(err)
				return c.JSON(code, body)
			}

			var bodyData map[string]interface{}
			if c.Request().Method != http.MethodGet {
				bodyBytes, err := io.ReadAll(c.Request().Body)
				if err == nil && len(bodyBytes) > 0 {
					_ = json.Unmarshal(bodyBytes, &bodyData)
					c.Request().Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				}
			}

			config := m.findMatchingConfig(c, configs, bodyData)
			log.Printf("Audit:RBACMiddleware. config=%v", config)
			if config == nil {
				return c.JSON(http.StatusBadRequest, model.ErrorResponse{
					Error: model.ErrorDetail{Code: "bad_request", Message: "No matching RBAC configuration for this request"},
				})
			}

			if config.Policy.Permission == "" && config.Policy.CheckScope == policy.CheckScopeNone {
				return next(c)
			}

			opReq := m.buildOperationRequest(c, config, callerID, bodyData)
			log.Printf("Audit:RBACMiddleware. opReq=%v", opReq)

			if config.Policy.NamespaceRequired && opReq.Namespace == "" {
				return c.JSON(http.StatusBadRequest, model.ErrorResponse{
					Error: model.ErrorDetail{Code: "bad_request", Message: "namespace is required for this operation"},
				})
			}

			if config.Policy.ResourceIDRequired && opReq.ResourceID == "" {
				return c.JSON(http.StatusBadRequest, model.ErrorResponse{
					Error: model.ErrorDetail{Code: "bad_request", Message: "resource_id is required for this operation"},
				})
			}

			if config.Policy.ParentResourceRequired && opReq.ParentResourceID == "" {
				return c.JSON(http.StatusBadRequest, model.ErrorResponse{
					Error: model.ErrorDetail{Code: "bad_request", Message: "parent_resource_id is required for this operation"},
				})
			}

			allowed, err := m.policyEngine.CheckOperationPermission(c.Request().Context(), m.repo, &opReq)
			log.Printf("Audit:RBACMiddleware. allowed=%v, err=%v", allowed, err)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, model.ErrorResponse{
					Error: model.ErrorDetail{Code: "internal_error", Message: err.Error()},
				})
			}

			if !allowed {
				return c.JSON(http.StatusForbidden, model.ErrorResponse{
					Error: model.ErrorDetail{Code: "forbidden", Message: "You do not have permission to perform this action"},
				})
			}

			return next(c)
		}
	}
}

func (m *RBACMiddleware) authenticateRequest(c echo.Context) (string, error) {
	if m.verifier == nil {
		callerID := c.Request().Header.Get("x-user-id")
		if callerID == "" {
			return "", service.ErrUnauthorized
		}
		return callerID, nil
	}

	token, err := extractBearerToken(c)
	if err != nil {
		return "", err
	}

	caller, err := m.verifier.VerifyToken(c.Request().Context(), token)
	if err != nil || caller.UserID == "" {
		return "", service.ErrUnauthorized
	}

	ctx := identity.WithCallerContext(c.Request().Context(), caller)
	c.SetRequest(c.Request().WithContext(ctx))
	return caller.UserID, nil
}

// findMatchingConfig finds the API config that matches the request conditions
func (m *RBACMiddleware) findMatchingConfig(c echo.Context, configs []*policy.APIConfig, bodyData map[string]interface{}) *policy.APIConfig {
	for _, config := range configs {
		if len(config.Policy.Condition) == 0 {
			return config
		}

		allMatch := true
		for condKey, condValue := range config.Policy.Condition {
			actualValue := m.extractValue(c, "query."+condKey, bodyData)
			if actualValue == "" {
				actualValue = m.extractValue(c, "body."+condKey, bodyData)
			}
			if actualValue != condValue {
				allMatch = false
				break
			}
		}

		if allMatch {
			return config
		}
	}

	return nil
}

// buildOperationRequest builds the OperationRequest from config and request params
func (m *RBACMiddleware) buildOperationRequest(c echo.Context, config *policy.APIConfig, callerID string, bodyData map[string]interface{}) policy.OperationRequest {
	opReq := policy.OperationRequest{
		CallerID:  callerID,
		Entity:    config.Entity,
		Operation: config.Operation,
	}

	if config.Policy.Params != nil {
		for paramName, paramSource := range config.Policy.Params {
			value := m.extractValue(c, paramSource, bodyData)
			switch paramName {
			case "namespace":
				opReq.Namespace = strings.ToUpper(strings.TrimSpace(value))
			case "resource_id":
				opReq.ResourceID = value
			case "resource_type":
				opReq.ResourceType = value
			case "parent_resource_id":
				opReq.ParentResourceID = value
			case "role":
				opReq.Role = value
			case "scope":
				opReq.Scope = value
			}
		}
	}

	return opReq
}

// extractValue extracts a value from the request based on source specification
// e.g., "body.namespace", "query.resource_id", "header.x-namespace"
func (m *RBACMiddleware) extractValue(c echo.Context, source string, bodyData map[string]interface{}) string {
	parts := strings.SplitN(source, ".", 2)
	if len(parts) != 2 {
		return ""
	}

	sourceType := parts[0]
	field := parts[1]

	switch sourceType {
	case "body":
		if bodyData != nil {
			if v, ok := bodyData[field]; ok {
				if str, ok := v.(string); ok {
					return str
				}
			}
		}
	case "query":
		return c.QueryParam(field)
	case "path":
		return c.Param(field)
	case "header":
		return c.Request().Header.Get(field)
	}

	return ""
}
