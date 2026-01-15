package tests

import (
	"context"
	"testing"

	"system/internal/system/client"
	"system/internal/system/graph"
	"system/internal/system/model"

	"github.com/99designs/gqlgen/graphql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthDirective(t *testing.T) {
	t.Run("allows request with valid permission", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool {
				return permission == "platform.system.create"
			},
			func(ownerID, namespace string) error {
				return nil // mock assign owner success
			},
			nil,
		)
		defer rbacServer.Close()

		rbacClient := client.NewRBACClient(rbacServer.URL)
		directive := graph.AuthDirective(rbacClient)

		// Create context with echo context containing x-user-id
		mockRepo := &MockSystemRepository{
			GetSystemByNamespaceFunc: func(ctx context.Context, namespace string) (*model.System, error) {
				return nil, nil // namespace not exists
			},
			CreateSystemFunc: func(ctx context.Context, system *model.System) error {
				return nil
			},
		}
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		// Test via GraphQL request
		query := `mutation { createSystem(namespace: "NS", name: "Test", owner: "u") { namespace } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "moderator"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		// If permission is allowed and no other errors, we pass directive check
		assert.Empty(t, resp.Errors)
		_ = directive // ensure it's used
	})

	t.Run("blocks request without x-user-id header", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		rbacClient := client.NewRBACClient(rbacServer.URL)
		mockRepo := &MockSystemRepository{}
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `mutation { createSystem(namespace: "NS", name: "Test", owner: "u") { namespace } }`
		rec := PerformGraphQL(e, query, nil, nil) // no x-user-id

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "unauthorized")
	})

	t.Run("blocks request when permission denied", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool {
				return false // always deny
			},
			nil, nil,
		)
		defer rbacServer.Close()

		rbacClient := client.NewRBACClient(rbacServer.URL)
		mockRepo := &MockSystemRepository{}
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `mutation { createSystem(namespace: "NS", name: "Test", owner: "u") { namespace } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "forbidden")
	})

	t.Run("validates namespace for namespaceRequired operations", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool {
				// Only allow if namespace is provided and matches
				return permission == "platform.system.read" && namespace == "TEST_NS"
			},
			nil, nil,
		)
		defer rbacServer.Close()

		rbacClient := client.NewRBACClient(rbacServer.URL)
		mockRepo := &MockSystemRepository{}
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		// systemDetail requires namespace
		query := `query { systemDetail(namespace: "TEST_NS") { namespace } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
	})
}

func TestDirectiveContextValues(t *testing.T) {
	t.Run("GetCallerID returns caller from context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), graph.CallerIDKey, "test_user")
		callerID, err := graph.GetCallerID(ctx)
		require.NoError(t, err)
		assert.Equal(t, "test_user", callerID)
	})

	t.Run("GetNamespace returns namespace from context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), graph.NamespaceKey, "TEST_NS")
		namespace := graph.GetNamespace(ctx)
		assert.Equal(t, "TEST_NS", namespace)
	})

	t.Run("GetNamespace returns empty when not set", func(t *testing.T) {
		ctx := context.Background()
		namespace := graph.GetNamespace(ctx)
		assert.Equal(t, "", namespace)
	})
}

// Suppress unused import warning
var _ graphql.Resolver
