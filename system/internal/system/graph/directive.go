package graph

import (
	"context"
	"fmt"
	"reflect"
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
func AuthDirective(rbacClient *client.RBACClient) func(ctx context.Context, obj interface{}, next graphql.Resolver, permission string, namespaceRequired *bool, namespaceField *string) (interface{}, error) {
	return func(ctx context.Context, obj interface{}, next graphql.Resolver, permission string, namespaceRequired *bool, namespaceField *string) (interface{}, error) {
		// 1. Get caller ID from context
		callerID, err := getCallerIDFromContext(ctx)
		if err != nil {
			return nil, err
		}

		// 2. Get namespace from GraphQL args if required
		namespace := ""
		if namespaceRequired != nil && *namespaceRequired {
			// Use namespaceField to determine the path, default to "namespace"
			fieldPath := "namespace"
			if namespaceField != nil && *namespaceField != "" {
				fieldPath = *namespaceField
			}
			namespace = getNamespaceFromPath(ctx, fieldPath)
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

// getNamespaceFromPath extracts namespace from GraphQL field arguments using a dot-separated path
// For example: "namespace" gets Args["namespace"], "input.namespace" gets Args["input"].Namespace
func getNamespaceFromPath(ctx context.Context, path string) string {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return ""
	}

	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return ""
	}

	// Start with Args as initial value
	var current interface{} = fc.Args
	for _, part := range parts {
		if current == nil {
			return ""
		}

		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			// Use reflection use struct field access
			current = getFieldByReflection(current, part)
		}
	}

	// Convert final value to string
	if ns, ok := current.(string); ok {
		return ns
	}
	return ""
}

// getFieldByReflection gets a field value from a struct using reflection
func getFieldByReflection(obj interface{}, fieldName string) interface{} {
	val := reflect.ValueOf(obj)

	// Handle pointer types
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return nil
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return nil
	}

	// Try to find field by name (case-insensitive first character for exported fields)
	field := val.FieldByNameFunc(func(name string) bool {
		return strings.EqualFold(name, fieldName) ||
			strings.EqualFold(strings.ToLower(name[:1])+name[1:], fieldName)
	})

	if !field.IsValid() {
		return nil
	}

	return field.Interface()
}

// getNamespaceFromArgs extracts namespace from GraphQL field arguments (deprecated, use getNamespaceFromPath)
func getNamespaceFromArgs(ctx context.Context) string {
	return getNamespaceFromPath(ctx, "namespace")
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
