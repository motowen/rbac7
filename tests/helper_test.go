package tests

import (
	"encoding/json"
	"net/http/httptest"
	"strings"

	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/router"
	"rbac7/internal/rbac/service"

	"github.com/labstack/echo/v4"
)

// SetupServer creates a basic Echo server without middleware (for unit testing)
func SetupServer() *echo.Echo {
	e := echo.New()
	return e
}

// SetupServerWithMiddleware creates a full Echo server with RBAC middleware (for integration testing)
// This uses the real router.RegisterRoutes which includes RBAC middleware
func SetupServerWithMiddleware(mockRepo *MockRBACRepository) *echo.Echo {
	e := echo.New()

	// Create service with mock repo (same repo for both since MockRBACRepository implements both interfaces)
	// Pass nil for adapter since tests don't use the adapter directly
	svc := service.NewService(mockRepo, mockRepo, nil)
	h := handler.NewSystemHandler(svc)

	// Create RBAC middleware
	policyLoader := svc.Policy.GetLoader()
	apiConfigs := policyLoader.LoadAPIConfigs(svc.Policy.GetEntityPolicies())

	// Register routes with middleware
	router.RegisterRoutes(e, h, svc.Policy, mockRepo, apiConfigs)

	return e
}

// SetupServerWithHandler creates a server with just handler registration (for testing without middleware)
// Use this when you want to test handler logic without RBAC middleware
func SetupServerWithHandler(mockRepo *MockRBACRepository) (*echo.Echo, *handler.SystemHandler) {
	e := echo.New()
	svc := service.NewService(mockRepo, mockRepo, nil) // nil adapter for tests
	h := handler.NewSystemHandler(svc)
	return e, h
}

// PerformRequest performs an HTTP request against the Echo server
func PerformRequest(e *echo.Echo, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	var bodyReader *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = strings.NewReader(string(b))
	} else {
		bodyReader = strings.NewReader("")
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}
