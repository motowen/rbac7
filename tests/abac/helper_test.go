package abac

import (
	"encoding/json"
	"net/http/httptest"
	"strings"

	"rbac7/internal/abac/handler"
	"rbac7/internal/abac/router"
	"rbac7/internal/abac/service"

	"github.com/labstack/echo/v4"
)

// SetupServer creates a full Echo server with ABAC routes
func SetupServer(mockSubjectRepo *MockABACRepository, mockPolicyRepo *MockPolicyRepository) *echo.Echo {
	e := echo.New()
	svc := service.NewService(mockSubjectRepo, mockPolicyRepo)
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
