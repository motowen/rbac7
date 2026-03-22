package abac

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"rbac7/internal/abac/handler"
	"rbac7/internal/abac/router"
	"rbac7/internal/abac/service"

	"github.com/labstack/echo/v4"
)

// SetupServer creates a full Echo server with ABAC routes
func SetupServer(mockSubjectRepo *MockABACRepository, mockPolicyRepo *MockPolicyRepository) *echo.Echo {
	e := echo.New()
	svc, err := service.NewService(mockSubjectRepo, mockPolicyRepo)
	if err != nil {
		// This should never happen in tests since the Rego file is embedded
		panic("failed to create ABAC service: " + err.Error())
	}
	h := handler.NewHandler(svc)
	router.RegisterRoutes(e, h)
	return e
}

// SetupServerT creates a full Echo server with ABAC routes, using testing.T for error reporting
func SetupServerT(t *testing.T, mockSubjectRepo *MockABACRepository, mockPolicyRepo *MockPolicyRepository) *echo.Echo {
	t.Helper()
	e := echo.New()
	svc, err := service.NewService(mockSubjectRepo, mockPolicyRepo)
	if err != nil {
		t.Fatalf("failed to create ABAC service: %v", err)
	}
	h := handler.NewHandler(svc)
	router.RegisterRoutes(e, h)
	return e
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
