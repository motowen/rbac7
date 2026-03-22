package handler

import (
	"crypto/rand"
	"encoding/hex"
	"rbac7/internal/abac/service"

	"github.com/labstack/echo/v4"
)

// extractCallerID extracts the caller user ID from the request header
func extractCallerID(c echo.Context) (string, error) {
	callerID := c.Request().Header.Get("x-user-id")
	if callerID == "" {
		return "", service.ErrUnauthorized
	}
	return callerID, nil
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		reqID := c.Request().Header.Get("x-request-id")
		if reqID == "" {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			reqID = hex.EncodeToString(b)
		}
		c.Set("request_id", reqID)
		c.Response().Header().Set("x-request-id", reqID)
		return next(c)
	}
}
