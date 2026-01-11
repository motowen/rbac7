package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/policy"
	"rbac7/internal/rbac/repository"

	"github.com/labstack/echo/v4"
)

// RBACMiddleware handles permission checking based on JSON configuration
type RBACMiddleware struct {
	policyEngine *policy.Engine
	repo         repository.RBACRepository
	apiConfigs   map[string][]*policy.APIConfig // key: "METHOD:PATH"
}

// NewRBACMiddleware creates a new RBAC middleware instance
func NewRBACMiddleware(engine *policy.Engine, repo repository.RBACRepository, apiConfigs map[string][]*policy.APIConfig) *RBACMiddleware {
	return &RBACMiddleware{
		policyEngine: engine,
		repo:         repo,
		apiConfigs:   apiConfigs,
	}
}

// Middleware returns the Echo middleware function
func (m *RBACMiddleware) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// 1. Build lookup key
			key := c.Request().Method + ":" + c.Path()

			// 2. Find matching API configs
			configs, exists := m.apiConfigs[key]
			if !exists {
				// No RBAC config for this path, pass through
				return next(c)
			}

			// 3. Extract caller ID
			callerID := c.Request().Header.Get("x-user-id")
			if callerID == "" {
				return c.JSON(http.StatusUnauthorized, model.ErrorResponse{
					Error: model.ErrorDetail{Code: "unauthorized", Message: "x-user-id header is required"},
				})
			}

			// 4. Parse request body for POST/PUT/DELETE (need to read and restore)
			var bodyData map[string]interface{}
			if c.Request().Method != http.MethodGet {
				bodyBytes, err := io.ReadAll(c.Request().Body)
				if err == nil && len(bodyBytes) > 0 {
					_ = json.Unmarshal(bodyBytes, &bodyData)
					// Restore body for handler
					c.Request().Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				}
			}

			// 5. Find matching config based on conditions
			config := m.findMatchingConfig(c, configs, bodyData)
			if config == nil {
				// No matching condition, pass through (shouldn't happen if JSON is complete)
				return next(c)
			}

			// 6. Skip if no permission required
			if config.Policy.Permission == "" && config.Policy.CheckScope == policy.CheckScopeNone {
				return next(c)
			}

			// 7. Build OperationRequest
			opReq := m.buildOperationRequest(c, config, callerID, bodyData)

			// 8. Check permission
			allowed, err := m.policyEngine.CheckOperationPermission(c.Request().Context(), m.repo, opReq)
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

			// 9. Permission granted, continue to handler
			return next(c)
		}
	}
}

// findMatchingConfig finds the API config that matches the request conditions
func (m *RBACMiddleware) findMatchingConfig(c echo.Context, configs []*policy.APIConfig, bodyData map[string]interface{}) *policy.APIConfig {
	for _, config := range configs {
		if config.Policy.Condition == nil || len(config.Policy.Condition) == 0 {
			// No condition means it's a catch-all
			return config
		}

		// Check all conditions
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

	// Return first config if no conditions match (fallback)
	if len(configs) > 0 {
		return configs[0]
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

	// Extract params based on config
	if config.Policy.Params != nil {
		for paramName, paramSource := range config.Policy.Params {
			value := m.extractValue(c, paramSource, bodyData)
			switch paramName {
			case "namespace":
				// Normalize namespace to uppercase (same as model validation)
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
