package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"system/internal/system/client"
	"system/internal/system/model"
	"system/internal/system/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================
// Library Widget Tests
// ============================================

func TestCreateLibraryWidget(t *testing.T) {
	t.Run("success - creates library widget", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			CreateLibraryWidgetFunc: func(ctx context.Context, widget *model.LibraryWidget) (*model.LibraryWidget, error) {
				widget.ID = "widget-123"
				widget.CreatedAt = time.Now()
				widget.UpdatedAt = time.Now()
				return widget, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation {
			createLibraryWidget(input: {
				type: "table"
				metadata: {name: "My Widget", description: "A test widget"}
				layout: {x: 0, y: 0, w: 4, h: 3}
			}) {
				id
				type
				metadata { name description }
				status
			}
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		assert.Equal(t, http.StatusOK, rec.Code)
		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			CreateLibraryWidget struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Metadata struct {
					Name        string  `json:"name"`
					Description *string `json:"description"`
				} `json:"metadata"`
				Status string `json:"status"`
			} `json:"createLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "widget-123", data.CreateLibraryWidget.ID)
		assert.Equal(t, "table", data.CreateLibraryWidget.Type)
		assert.Equal(t, "My Widget", data.CreateLibraryWidget.Metadata.Name)
		assert.Equal(t, "DRAFT", data.CreateLibraryWidget.Status)
	})
}

func TestUpdateLibraryWidget(t *testing.T) {
	t.Run("success - updates library widget", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			UpdateLibraryWidgetFunc: func(ctx context.Context, id string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:       id,
					Type:     "chart",
					Metadata: model.WidgetMetadata{Name: "Updated Widget"},
					Layout:   model.LibraryWidgetLayout{X: 0, Y: 0, W: 4, H: 3},
					Status:   "PUBLISHED",
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation {
			updateLibraryWidget(input: {id: "widget-123", status: PUBLISHED}) {
				id
				status
			}
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			UpdateLibraryWidget struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"updateLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "widget-123", data.UpdateLibraryWidget.ID)
		assert.Equal(t, "PUBLISHED", data.UpdateLibraryWidget.Status)
	})

	t.Run("error - widget not found", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			UpdateLibraryWidgetFunc: func(ctx context.Context, id string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error) {
				return nil, nil // not found
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation { updateLibraryWidget(input: {id: "nonexistent"}) { id } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "not found")
	})
}

func TestDeleteLibraryWidget(t *testing.T) {
	t.Run("success - deletes library widget", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			DeleteLibraryWidgetFunc: func(ctx context.Context, id string) error {
				return nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation { deleteLibraryWidget(id: "widget-123") }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
	})
}

func TestLibraryWidgets(t *testing.T) {
	t.Run("success - returns all library widgets", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetsFunc: func(ctx context.Context) ([]*model.LibraryWidget, error) {
				return []*model.LibraryWidget{
					{ID: "w1", Type: "table", Metadata: model.WidgetMetadata{Name: "Widget 1"}, Layout: model.LibraryWidgetLayout{X: 0, Y: 0, W: 4, H: 3}, Status: "PUBLISHED"},
					{ID: "w2", Type: "chart", Metadata: model.WidgetMetadata{Name: "Widget 2"}, Layout: model.LibraryWidgetLayout{X: 4, Y: 0, W: 4, H: 3}, Status: "DRAFT"},
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `query { libraryWidgets { id type metadata { name } status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			LibraryWidgets []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Status string `json:"status"`
			} `json:"libraryWidgets"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Len(t, data.LibraryWidgets, 2)
		assert.Equal(t, "w1", data.LibraryWidgets[0].ID)
		assert.Equal(t, "w2", data.LibraryWidgets[1].ID)
	})

	t.Run("success - returns empty array when no widgets", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetsFunc: func(ctx context.Context) ([]*model.LibraryWidget, error) {
				return []*model.LibraryWidget{}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `query { libraryWidgets { id } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
	})
}

func TestLibraryWidget(t *testing.T) {
	t.Run("success - returns library widget by id", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:       id,
					Type:     "table",
					Metadata: model.WidgetMetadata{Name: "Test Widget"},
					Layout:   model.LibraryWidgetLayout{X: 0, Y: 0, W: 4, H: 3},
					Status:   "PUBLISHED",
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `query { libraryWidget(id: "widget-123") { id type metadata { name } } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			LibraryWidget struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"libraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "widget-123", data.LibraryWidget.ID)
	})

	t.Run("returns null - widget not found", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return nil, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `query { libraryWidget(id: "nonexistent") { id } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
		// Data should contain null for libraryWidget
	})
}

// ============================================
// Dashboard Widget Tests
// ============================================

func TestCreateDashboardWidget(t *testing.T) {
	t.Run("success - creates dashboard widget", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:       id,
					Type:     "table",
					Metadata: model.WidgetMetadata{Name: "Source Widget"},
					Layout:   model.LibraryWidgetLayout{X: 0, Y: 0, W: 4, H: 3},
					Status:   "PUBLISHED",
				}, nil
			},
			CreateDashboardWidgetFunc: func(ctx context.Context, widget *model.DashboardWidget) (*model.DashboardWidget, error) {
				widget.ID = "dw-123"
				widget.CreatedAt = time.Now()
				widget.UpdatedAt = time.Now()
				return widget, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation {
			createDashboardWidget(input: {
				dashboardId: "dashboard-1"
				libraryWidgetId: "lw-123"
				layout: {x: 0, y: 0, w: 6, h: 4}
			}) {
				id
				dashboardId
				libraryWidgetId
				layout { x y w h }
				libraryWidget { id type metadata { name } }
			}
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			CreateDashboardWidget struct {
				ID              string `json:"id"`
				DashboardID     string `json:"dashboardId"`
				LibraryWidgetID string `json:"libraryWidgetId"`
				Layout          struct {
					X int `json:"x"`
					Y int `json:"y"`
					W int `json:"w"`
					H int `json:"h"`
				} `json:"layout"`
				LibraryWidget struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"libraryWidget"`
			} `json:"createDashboardWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "dw-123", data.CreateDashboardWidget.ID)
		assert.Equal(t, "dashboard-1", data.CreateDashboardWidget.DashboardID)
		assert.Equal(t, 6, data.CreateDashboardWidget.Layout.W)
	})

	t.Run("error - library widget not found", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return nil, nil // not found
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation {
			createDashboardWidget(input: {
				dashboardId: "dashboard-1"
				libraryWidgetId: "nonexistent"
				layout: {x: 0, y: 0, w: 4, h: 3}
			}) { id }
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "library widget not found")
	})
}

func TestUpdateDashboardWidget(t *testing.T) {
	t.Run("success - updates dashboard widget layout", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			UpdateDashboardWidgetFunc: func(ctx context.Context, id string, layout *model.DashboardWidgetLayout) (*model.DashboardWidget, error) {
				return &model.DashboardWidget{
					ID:              id,
					DashboardID:     "dashboard-1",
					LibraryWidgetID: "lw-123",
					Layout:          *layout,
				}, nil
			},
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:       id,
					Type:     "table",
					Metadata: model.WidgetMetadata{Name: "Widget"},
					Layout:   model.LibraryWidgetLayout{X: 0, Y: 0, W: 4, H: 3},
					Status:   "PUBLISHED",
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation {
			updateDashboardWidget(input: {id: "dw-123", layout: {x: 2, y: 2, w: 8, h: 6}}) {
				id
				layout { x y w h }
			}
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			UpdateDashboardWidget struct {
				ID     string `json:"id"`
				Layout struct {
					X int `json:"x"`
					Y int `json:"y"`
					W int `json:"w"`
					H int `json:"h"`
				} `json:"layout"`
			} `json:"updateDashboardWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "dw-123", data.UpdateDashboardWidget.ID)
		assert.Equal(t, 8, data.UpdateDashboardWidget.Layout.W)
		assert.Equal(t, 6, data.UpdateDashboardWidget.Layout.H)
	})
}

func TestDeleteDashboardWidget(t *testing.T) {
	t.Run("success - deletes dashboard widget", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			DeleteDashboardWidgetFunc: func(ctx context.Context, id string) error {
				return nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation { deleteDashboardWidget(id: "dw-123") }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
	})
}

func TestDashboardWidgets(t *testing.T) {
	t.Run("success - returns dashboard widgets", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetDashboardWidgetsFunc: func(ctx context.Context, dashboardID string) ([]*model.DashboardWidget, error) {
				return []*model.DashboardWidget{
					{ID: "dw1", DashboardID: dashboardID, LibraryWidgetID: "lw1", Layout: model.DashboardWidgetLayout{X: 0, Y: 0, W: 4, H: 3}},
					{ID: "dw2", DashboardID: dashboardID, LibraryWidgetID: "lw2", Layout: model.DashboardWidgetLayout{X: 4, Y: 0, W: 4, H: 3}},
				}, nil
			},
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:       id,
					Type:     "table",
					Metadata: model.WidgetMetadata{Name: "Widget " + id},
					Layout:   model.LibraryWidgetLayout{X: 0, Y: 0, W: 4, H: 3},
					Status:   "PUBLISHED",
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `query { dashboardWidgets(dashboardId: "dashboard-1") { id dashboardId layout { x y w h } } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			DashboardWidgets []struct {
				ID          string `json:"id"`
				DashboardID string `json:"dashboardId"`
				Layout      struct {
					X int `json:"x"`
					Y int `json:"y"`
					W int `json:"w"`
					H int `json:"h"`
				} `json:"layout"`
			} `json:"dashboardWidgets"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Len(t, data.DashboardWidgets, 2)
		assert.Equal(t, "dw1", data.DashboardWidgets[0].ID)
		assert.Equal(t, "dashboard-1", data.DashboardWidgets[0].DashboardID)
	})
}

func TestDashboardWidget(t *testing.T) {
	t.Run("success - returns dashboard widget by id", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetDashboardWidgetFunc: func(ctx context.Context, id string) (*model.DashboardWidget, error) {
				return &model.DashboardWidget{
					ID:              id,
					DashboardID:     "dashboard-1",
					LibraryWidgetID: "lw-123",
					Layout:          model.DashboardWidgetLayout{X: 0, Y: 0, W: 6, H: 4},
				}, nil
			},
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:       id,
					Type:     "chart",
					Metadata: model.WidgetMetadata{Name: "Chart Widget"},
					Layout:   model.LibraryWidgetLayout{X: 0, Y: 0, W: 4, H: 3},
					Status:   "PUBLISHED",
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `query { dashboardWidget(id: "dw-123") { id dashboardId libraryWidget { id type } } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			DashboardWidget struct {
				ID            string `json:"id"`
				DashboardID   string `json:"dashboardId"`
				LibraryWidget struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"libraryWidget"`
			} `json:"dashboardWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "dw-123", data.DashboardWidget.ID)
		assert.Equal(t, "chart", data.DashboardWidget.LibraryWidget.Type)
	})
}
