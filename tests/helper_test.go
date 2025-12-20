package tests

import (
	"encoding/json"
	"net/http/httptest"
	"strings"

	"github.com/labstack/echo/v4"
)

// Mock DB/Service interfaces would go here or in a generic mock package.
// For now, we provide the basic Echo setup.

func SetupServer() *echo.Echo {
	e := echo.New()
	return e
}

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
