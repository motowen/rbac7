package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/policy"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// Helper to setup Echo with the middleware for unit testing
func setupMiddlewareTestEcho(mockRepo *MockRBACRepository, configs map[string][]*policy.APIConfig) *echo.Echo {
	policyEngine, _ := policy.NewEngine()
	rbacMiddleware := handler.NewRBACMiddleware(policyEngine, mockRepo, configs)

	e := echo.New()
	e.Use(rbacMiddleware.Middleware())
	e.POST("/api/v1/user_roles", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.POST("/api/v1/user_roles/resources", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.DELETE("/api/v1/user_roles/resources", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	return e
}

// TestRBACMiddlewareValidation tests the middleware validation logic
// These are unit tests that directly test middleware behavior with custom configs
func TestRBACMiddlewareValidation(t *testing.T) {

	t.Run("namespace_required blocks request when namespace is empty", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)

		// Create config with namespace_required=true
		configs := map[string][]*policy.APIConfig{
			"POST:/api/v1/user_roles": {
				{
					Entity:    "system",
					Operation: "assign_role",
					Policy: &policy.OperationPolicy{
						Method:            "POST",
						Path:              "/api/v1/user_roles",
						Permission:        "platform.system.add_member",
						CheckScope:        policy.CheckScopeSystem,
						NamespaceRequired: true, // This should block empty namespace
						Params: map[string]string{
							"namespace": "body.namespace",
						},
						Condition: map[string]string{
							"scope": "system",
						},
					},
				},
			},
		}

		e := setupMiddlewareTestEcho(mockRepo, configs)

		// Request body with empty namespace
		body := map[string]interface{}{
			"user_id":   "u_1",
			"role":      "admin",
			"namespace": "", // Empty - should be blocked by middleware
			"scope":     "system",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/user_roles", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-user-id", "caller")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Should return 400 because namespace is required but empty
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "namespace is required")

		// Verify HasAnySystemRole was NOT called - middleware blocked before permission check
		mockRepo.AssertNotCalled(t, "HasAnySystemRole")
	})

	t.Run("resource_id_required blocks request when resource_id is empty", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)

		// Create config with resource_id_required=true
		configs := map[string][]*policy.APIConfig{
			"POST:/api/v1/user_roles/resources": {
				{
					Entity:    "dashboard",
					Operation: "assign_role",
					Policy: &policy.OperationPolicy{
						Method:             "POST",
						Path:               "/api/v1/user_roles/resources",
						Permission:         "resource.dashboard.add_member",
						CheckScope:         policy.CheckScopeResource,
						ResourceIDRequired: true, // This should block empty resource_id
						Params: map[string]string{
							"resource_id":   "body.resource_id",
							"resource_type": "body.resource_type",
						},
						Condition: map[string]string{
							"resource_type": "dashboard",
						},
					},
				},
			},
		}

		e := setupMiddlewareTestEcho(mockRepo, configs)

		// Request body with empty resource_id
		body := map[string]interface{}{
			"user_id":       "u_1",
			"role":          "viewer",
			"resource_id":   "", // Empty - should be blocked by middleware
			"resource_type": "dashboard",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/user_roles/resources", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-user-id", "caller")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Should return 400 because resource_id is required but empty
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "resource_id is required")

		// Verify HasAnyResourceRole was NOT called
		mockRepo.AssertNotCalled(t, "HasAnyResourceRole")
	})

	t.Run("parent_resource_required blocks request when parent_resource_id is empty", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)

		// Create config with parent_resource_required=true
		configs := map[string][]*policy.APIConfig{
			"DELETE:/api/v1/user_roles/resources": {
				{
					Entity:    "dashboard_widget",
					Operation: "delete_viewer",
					Policy: &policy.OperationPolicy{
						Method:                 "DELETE",
						Path:                   "/api/v1/user_roles/resources",
						Permission:             "resource.dashboard.add_widget_viewer",
						CheckScope:             policy.CheckScopeParentResource,
						ParentResourceRequired: true, // This should block empty parent_resource_id
						Params: map[string]string{
							"resource_id":        "query.resource_id",
							"resource_type":      "query.resource_type",
							"parent_resource_id": "query.parent_resource_id",
						},
						Condition: map[string]string{
							"resource_type": "dashboard_widget",
						},
					},
				},
			},
		}

		e := setupMiddlewareTestEcho(mockRepo, configs)

		// Request without parent_resource_id
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/user_roles/resources?resource_id=w1&resource_type=dashboard_widget&user_id=u1", nil)
		req.Header.Set("x-user-id", "caller")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Should return 400 because parent_resource_id is required but empty
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "parent_resource_id is required")

		// Verify HasAnyResourceRole was NOT called
		mockRepo.AssertNotCalled(t, "HasAnyResourceRole")
	})

	t.Run("no matching config returns 400 not passthrough", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)

		// Create config that only matches resource_type=dashboard
		configs := map[string][]*policy.APIConfig{
			"POST:/api/v1/user_roles/resources": {
				{
					Entity:    "dashboard",
					Operation: "assign_role",
					Policy: &policy.OperationPolicy{
						Method:     "POST",
						Path:       "/api/v1/user_roles/resources",
						Permission: "resource.dashboard.add_member",
						CheckScope: policy.CheckScopeResource,
						Params: map[string]string{
							"resource_id":   "body.resource_id",
							"resource_type": "body.resource_type",
						},
						Condition: map[string]string{
							"resource_type": "dashboard", // Only matches dashboard
						},
					},
				},
			},
		}

		e := setupMiddlewareTestEcho(mockRepo, configs)

		// Request with unknown resource_type that doesn't match any condition
		body := map[string]interface{}{
			"user_id":       "u_1",
			"role":          "viewer",
			"resource_id":   "r1",
			"resource_type": "unknown_type", // Doesn't match condition
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/user_roles/resources", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-user-id", "caller")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		// Should return 400 because no config matches (not passthrough to handler)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "No matching RBAC configuration")
	})
}
