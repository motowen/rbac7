package handler

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/labstack/echo/v4"
)

func RequestIDMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		reqID := c.Request().Header.Get(echo.HeaderXRequestID)
		if reqID == "" {
			// Generate random ID
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			reqID = hex.EncodeToString(b)
		}
		c.Response().Header().Set(echo.HeaderXRequestID, reqID)
		return next(c)
	}
}
