package graph

import (
	"context"
	"fmt"
	"strings"

	"system/internal/system/client"

	"github.com/99designs/gqlgen/graphql"
	"github.com/labstack/echo/v4"
)

// ContextKey is the key type for context values
type ContextKey string

const (
	// CallerIDKey is the context key for caller ID
	CallerIDKey ContextKey = "caller_id"
	// NamespaceKey is the context key for namespace (extracted from args)
	NamespaceKey ContextKey = "namespace"
)

// AuthDirective creates a directive handler for the @auth directive
func AuthDirective(rbacClient *client.RBACClient) func(ctx context.Context, obj interface{}, next graphql.Resolver, permission string, namespaceRequired *bool) (interface{}, error) {
	return func(ctx context.Context, obj interface{}, next graphql.Resolver, permission string, namespaceRequired *bool) (interface{}, error) {
		// 1. Get caller ID from context
		callerID, err := getCallerIDFromContext(ctx)
		if err != nil {
			return nil, err
		}

		// 2. Get namespace from GraphQL args if required
		namespace := ""
		if namespaceRequired != nil && *namespaceRequired {
			namespace = getNamespaceFromArgs(ctx)
			if namespace == "" {
				return nil, fmt.Errorf("namespace is required for this operation")
			}
			namespace = strings.ToUpper(strings.TrimSpace(namespace))
		}

		// 3. Check permission via RBAC
		allowed, err := rbacClient.CheckPermission(ctx, callerID, permission, namespace)
		if err != nil {
			return nil, fmt.Errorf("permission check failed: %w", err)
		}
		if !allowed {
			return nil, fmt.Errorf("forbidden: no permission %s", permission)
		}

		// 4. Store caller ID and namespace in context for resolver use
		ctx = context.WithValue(ctx, CallerIDKey, callerID)
		if namespace != "" {
			ctx = context.WithValue(ctx, NamespaceKey, namespace)
		}

		// 5. Continue to resolver
		return next(ctx)
	}
}

// getCallerIDFromContext extracts caller ID from echo context
func getCallerIDFromContext(ctx context.Context) (string, error) {
	ec, ok := ctx.Value("echo_context").(echo.Context)
	if !ok {
		return "", fmt.Errorf("unauthorized: missing context")
	}
	callerID := ec.Request().Header.Get("x-user-id")
	if callerID == "" {
		return "", fmt.Errorf("unauthorized: missing x-user-id header")
	}
	return callerID, nil
}

// getNamespaceFromArgs extracts namespace from GraphQL field arguments
func getNamespaceFromArgs(ctx context.Context) string {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return ""
	}

	// Try to get namespace from args
	if ns, ok := fc.Args["namespace"].(string); ok {
		return ns
	}
	return ""
}

// GetCallerID gets caller ID from context (for use in resolvers)
func GetCallerID(ctx context.Context) (string, error) {
	if callerID, ok := ctx.Value(CallerIDKey).(string); ok {
		return callerID, nil
	}
	// Fallback to echo context for operations without @auth directive
	return getCallerIDFromContext(ctx)
}

// GetNamespace gets namespace from context (for use in resolvers)
func GetNamespace(ctx context.Context) string {
	if ns, ok := ctx.Value(NamespaceKey).(string); ok {
		return ns
	}
	return ""
}
