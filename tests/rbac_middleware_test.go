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
	"github.com/stretchr/testify/mock"
)

// setupRBACMiddlewareTest creates a test Echo instance with real policy configs
func setupRBACMiddlewareTest(mockRepo *MockRBACRepository) *echo.Echo {
	policyEngine, _ := policy.NewEngine()
	apiConfigs := policyEngine.GetLoader().LoadAPIConfigs(policyEngine.GetEntityPolicies())
	rbacMiddleware := handler.NewRBACMiddleware(policyEngine, mockRepo, apiConfigs)

	e := echo.New()
	e.Use(rbacMiddleware.Middleware())

	// Register all API routes that go through RBAC middleware
	// System Scope Routes
	e.POST("/api/v1/user_roles/owner", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.PUT("/api/v1/user_roles/owner", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.POST("/api/v1/user_roles", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.POST("/api/v1/user_roles/batch", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.DELETE("/api/v1/user_roles", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.GET("/api/v1/user_roles/me", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.GET("/api/v1/user_roles", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	// Resource Scope Routes
	e.POST("/api/v1/user_roles/resources/owner", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.PUT("/api/v1/user_roles/resources/owner", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.POST("/api/v1/user_roles/resources", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.POST("/api/v1/user_roles/resources/batch", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	e.DELETE("/api/v1/user_roles/resources", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	return e
}

// Helper function to perform request
func performMiddlewareRequest(e *echo.Echo, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		bodyBytes, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// ============================================================================
// Test: Config Matching - Verify correct operation is matched based on conditions
// ============================================================================

func TestRBACMiddlewareConfigMatching(t *testing.T) {
	headers := map[string]string{"x-user-id": "caller"}

	// === system.json operations ===
	t.Run("system/assign_owner matches POST /user_roles/owner", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		// assign_owner uses check_scope: global, no namespace required
		mockRepo.On("HasAnySystemRole", mock.Anything, "caller", "", mock.Anything).Return(true, nil)

		body := map[string]interface{}{"namespace": "ns1", "user_id": "u1"}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles/owner", body, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertCalled(t, "HasAnySystemRole", mock.Anything, "caller", "", mock.Anything)
	})

	t.Run("system/transfer_owner matches PUT /user_roles/owner", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		// transfer_owner uses check_scope: system, namespace_required: true
		mockRepo.On("HasAnySystemRole", mock.Anything, "caller", "NS1", mock.Anything).Return(true, nil)

		body := map[string]interface{}{"namespace": "ns1", "new_owner_id": "u2"}
		rec := performMiddlewareRequest(e, http.MethodPut, "/api/v1/user_roles/owner", body, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRepo.AssertCalled(t, "HasAnySystemRole", mock.Anything, "caller", "NS1", mock.Anything)
	})

	t.Run("system/assign_user_role matches POST /user_roles with scope=system", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "caller", "NS1", mock.Anything).Return(true, nil)

		body := map[string]interface{}{"namespace": "ns1", "user_id": "u1", "role": "admin", "scope": "system"}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles", body, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("system/delete_user_role matches DELETE /user_roles with namespace", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "caller", "NS1", mock.Anything).Return(true, nil)

		rec := performMiddlewareRequest(e, http.MethodDelete, "/api/v1/user_roles?namespace=ns1&user_id=u1", nil, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("system/get_members matches GET /user_roles with scope=system", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "caller", "NS1", mock.Anything).Return(true, nil)

		rec := performMiddlewareRequest(e, http.MethodGet, "/api/v1/user_roles?scope=system&namespace=ns1", nil, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	// === dashboard.json operations ===
	t.Run("dashboard/assign_owner matches POST /user_roles/resources/owner with resource_type=dashboard", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		// assign_owner has check_scope: none, no permission check
		body := map[string]interface{}{"resource_id": "d1", "resource_type": "dashboard"}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles/resources/owner", body, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
		// No permission check should be called
		mockRepo.AssertNotCalled(t, "HasAnyResourceRole")
	})

	t.Run("dashboard/transfer_owner matches PUT /user_roles/resources/owner with resource_type=dashboard", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "d1", "dashboard", mock.Anything).Return(true, nil)

		body := map[string]interface{}{"resource_id": "d1", "resource_type": "dashboard", "new_owner_id": "u2"}
		rec := performMiddlewareRequest(e, http.MethodPut, "/api/v1/user_roles/resources/owner", body, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("dashboard/assign_user_role matches POST /user_roles/resources with resource_type=dashboard", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "d1", "dashboard", mock.Anything).Return(true, nil)

		body := map[string]interface{}{"resource_id": "d1", "resource_type": "dashboard", "user_id": "u1", "role": "viewer"}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles/resources", body, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("dashboard/delete_user_role matches DELETE /user_roles/resources with resource_type=dashboard", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "d1", "dashboard", mock.Anything).Return(true, nil)

		rec := performMiddlewareRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?resource_id=d1&resource_type=dashboard&user_id=u1", nil, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("dashboard/get_members matches GET /user_roles with scope=resource&resource_type=dashboard", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "d1", "dashboard", mock.Anything).Return(true, nil)

		rec := performMiddlewareRequest(e, http.MethodGet, "/api/v1/user_roles?scope=resource&resource_type=dashboard&resource_id=d1", nil, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	// === dashboard_widget.json operations ===
	t.Run("dashboard_widget/assign_viewer matches POST /user_roles/resources with resource_type=dashboard_widget&role=viewer", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		// Checks parent resource (dashboard)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "d1", "dashboard", mock.Anything).Return(true, nil)

		body := map[string]interface{}{
			"resource_id":        "w1",
			"resource_type":      "dashboard_widget",
			"parent_resource_id": "d1",
			"user_id":            "u1",
			"role":               "viewer",
		}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles/resources", body, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("dashboard_widget/delete_viewer matches DELETE /user_roles/resources with resource_type=dashboard_widget", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "d1", "dashboard", mock.Anything).Return(true, nil)

		rec := performMiddlewareRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?resource_id=w1&resource_type=dashboard_widget&parent_resource_id=d1&user_id=u1", nil, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	// === library_widget.json operations (now use resources API with resource_type=library_widget) ===
	t.Run("library_widget/assign_viewers_batch matches POST /user_roles/resources/batch with resource_type=library_widget", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "caller", "NS1", mock.Anything).Return(true, nil)

		body := map[string]interface{}{"namespace": "ns1", "resource_id": "lw1", "resource_type": "library_widget", "role": "viewer", "user_ids": []string{"u1"}}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles/resources/batch", body, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("library_widget/delete_viewer matches DELETE /user_roles/resources with resource_type=library_widget", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "caller", "NS1", mock.Anything).Return(true, nil)

		rec := performMiddlewareRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?namespace=ns1&resource_id=lw1&resource_type=library_widget&user_id=u1", nil, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// ============================================================================
// Test: Required Parameters Validation
// ============================================================================

func TestRBACMiddlewareRequiredParams(t *testing.T) {
	headers := map[string]string{"x-user-id": "caller"}

	t.Run("namespace_required blocks when namespace is empty", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		// system/transfer_owner requires namespace
		body := map[string]interface{}{"namespace": "", "new_owner_id": "u2"}
		rec := performMiddlewareRequest(e, http.MethodPut, "/api/v1/user_roles/owner", body, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "namespace is required")
		mockRepo.AssertNotCalled(t, "HasAnySystemRole")
	})

	t.Run("resource_id_required blocks when resource_id is empty", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		// dashboard/transfer_owner requires resource_id
		body := map[string]interface{}{"resource_id": "", "resource_type": "dashboard", "new_owner_id": "u2"}
		rec := performMiddlewareRequest(e, http.MethodPut, "/api/v1/user_roles/resources/owner", body, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "resource_id is required")
		mockRepo.AssertNotCalled(t, "HasAnyResourceRole")
	})

	t.Run("parent_resource_required blocks when parent_resource_id is empty", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		// dashboard_widget/delete_viewer requires parent_resource_id
		rec := performMiddlewareRequest(e, http.MethodDelete, "/api/v1/user_roles/resources?resource_id=w1&resource_type=dashboard_widget&user_id=u1", nil, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "parent_resource_id is required")
		mockRepo.AssertNotCalled(t, "HasAnyResourceRole")
	})
}

// ============================================================================
// Test: No Matching Config Returns 400
// ============================================================================

func TestRBACMiddlewareNoMatchingConfig(t *testing.T) {
	headers := map[string]string{"x-user-id": "caller"}

	t.Run("unknown resource_type returns 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		body := map[string]interface{}{"resource_id": "x1", "resource_type": "unknown_type", "user_id": "u1", "role": "viewer"}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles/resources", body, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "No matching RBAC configuration")
	})

	t.Run("dashboard_widget without role=viewer returns 400 for assign", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		// dashboard_widget assign_viewer requires role=viewer condition
		body := map[string]interface{}{
			"resource_id":        "w1",
			"resource_type":      "dashboard_widget",
			"parent_resource_id": "d1",
			"user_id":            "u1",
			"role":               "admin", // Not matching condition role=viewer
		}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles/resources", body, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// ============================================================================
// Test: Permission Denied Returns 403
// ============================================================================

func TestRBACMiddlewarePermissionDenied(t *testing.T) {
	headers := map[string]string{"x-user-id": "caller"}

	t.Run("system operation returns 403 when no permission", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "caller", "NS1", mock.Anything).Return(false, nil)

		body := map[string]interface{}{"namespace": "ns1", "user_id": "u1", "role": "admin"}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles", body, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("resource operation returns 403 when no permission", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "d1", "dashboard", mock.Anything).Return(false, nil)

		body := map[string]interface{}{"resource_id": "d1", "resource_type": "dashboard", "user_id": "u1", "role": "viewer"}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles/resources", body, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("parent_resource operation returns 403 when no permission on parent", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		// No permission on parent dashboard
		mockRepo.On("HasAnyResourceRole", mock.Anything, "caller", "d1", "dashboard", mock.Anything).Return(false, nil)

		body := map[string]interface{}{
			"resource_id":        "w1",
			"resource_type":      "dashboard_widget",
			"parent_resource_id": "d1",
			"user_id":            "u1",
			"role":               "viewer",
		}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles/resources", body, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

// ============================================================================
// Test: Unauthorized Returns 401
// ============================================================================

func TestRBACMiddlewareUnauthorized(t *testing.T) {
	t.Run("missing x-user-id returns 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := setupRBACMiddlewareTest(mockRepo)

		body := map[string]interface{}{"namespace": "ns1", "user_id": "u1"}
		rec := performMiddlewareRequest(e, http.MethodPost, "/api/v1/user_roles/owner", body, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
