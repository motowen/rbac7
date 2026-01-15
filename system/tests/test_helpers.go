package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"system/internal/system/client"
	"system/internal/system/graph"
	"system/internal/system/repository"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/labstack/echo/v4"
)

// TestServer provides a test GraphQL server
type TestServer struct {
	Echo       *echo.Echo
	Repo       *MockSystemRepository
	RBACClient *MockRBACClient
}

// RBACClientInterface defines the interface for RBAC client (for mocking)
type RBACClientInterface interface {
	CheckPermission(ctx context.Context, callerID, permission, namespace string) (bool, error)
	AssignSystemOwner(ctx context.Context, callerID, ownerID, namespace string) error
	GetUserRolesMe(ctx context.Context, callerID string) ([]client.UserRole, error)
}

// NewTestServer creates a test server with mock dependencies
func NewTestServer() *TestServer {
	mockRepo := &MockSystemRepository{}
	mockRBAC := &MockRBACClient{}

	// Create test echo server
	e := echo.New()

	// Note: We need to wrap mock RBAC client to match the real client type
	// For now, we'll use a real client with a test HTTP server
	return &TestServer{
		Echo:       e,
		Repo:       mockRepo,
		RBACClient: mockRBAC,
	}
}

// SetupGraphQL sets up the GraphQL handler with mocks
func (ts *TestServer) SetupGraphQL(rbacClient *client.RBACClient) *handler.Server {
	cfg := graph.Config{
		Resolvers: &graph.Resolver{
			Repo:       ts.Repo,
			RBACClient: rbacClient,
		},
		Directives: graph.DirectiveRoot{
			Auth: graph.AuthDirective(rbacClient),
		},
	}
	return handler.NewDefaultServer(graph.NewExecutableSchema(cfg))
}

// SetupGraphQLWithMockRepo sets up GraphQL with mock repo but real RBAC directive
func SetupGraphQLWithMockRepo(repo repository.SystemRepository, rbacClient *client.RBACClient) *echo.Echo {
	e := echo.New()

	cfg := graph.Config{
		Resolvers: &graph.Resolver{
			Repo:       repo,
			RBACClient: rbacClient,
		},
		Directives: graph.DirectiveRoot{
			Auth: graph.AuthDirective(rbacClient),
		},
	}

	srv := handler.NewDefaultServer(graph.NewExecutableSchema(cfg))

	e.POST("/graphql", func(c echo.Context) error {
		ctx := context.WithValue(c.Request().Context(), "echo_context", c)
		c.SetRequest(c.Request().WithContext(ctx))
		srv.ServeHTTP(c.Response(), c.Request())
		return nil
	})

	return e
}

// GraphQLRequest represents a GraphQL request
type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLResponse represents a GraphQL response
type GraphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

// PerformGraphQL performs a GraphQL request
func PerformGraphQL(e *echo.Echo, query string, variables map[string]interface{}, headers map[string]string) *httptest.ResponseRecorder {
	reqBody := GraphQLRequest{
		Query:     query,
		Variables: variables,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// ParseGraphQLResponse parses a GraphQL response
func ParseGraphQLResponse(rec *httptest.ResponseRecorder) (*GraphQLResponse, error) {
	var resp GraphQLResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateMockRBACServer creates a mock RBAC HTTP server
func CreateMockRBACServer(checkPermission func(permission, namespace string) bool, assignOwner func(ownerID, namespace string) error, getUserRoles func(callerID string) []client.UserRole) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callerID := r.Header.Get("x-user-id")
		if callerID == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch {
		case r.URL.Path == "/api/v1/permissions/check" && r.Method == http.MethodPost:
			var req struct {
				Permission string `json:"permission"`
				Namespace  string `json:"namespace"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			allowed := checkPermission(req.Permission, req.Namespace)
			json.NewEncoder(w).Encode(map[string]bool{"allowed": allowed})

		case r.URL.Path == "/api/v1/user_roles/owner" && r.Method == http.MethodPost:
			var req struct {
				UserID    string `json:"user_id"`
				Namespace string `json:"namespace"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			if err := assignOwner(req.UserID, req.Namespace); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "success"})

		case r.URL.Path == "/api/v1/user_roles/me" && r.Method == http.MethodGet:
			roles := getUserRoles(callerID)
			json.NewEncoder(w).Encode(roles)

		default:
			http.NotFound(w, r)
		}
	}))
}
