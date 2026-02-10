package repository

import (
	"context"
	"errors"
	"time"

	"system/internal/system/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	ErrDashboardNotFound     = errors.New("dashboard not found")
	ErrInvalidStatusChange   = errors.New("invalid status change")
	ErrWidgetNotFound        = errors.New("dashboard widget not found")
	ErrLibraryWidgetNotFound = errors.New("library widget not found")
)

// DashboardRepository defines the interface for dashboard data access
type DashboardRepository interface {
	// Dashboard CRUD
	CreateDashboard(ctx context.Context, dashboard *model.Dashboard) (*model.Dashboard, error)
	GetDashboard(ctx context.Context, id string) (*model.Dashboard, error)
	GetDashboards(ctx context.Context) ([]*model.Dashboard, error)
	UpdateDashboard(ctx context.Context, id string, update *DashboardUpdate) (*model.Dashboard, error)
	UpdateDashboardStatus(ctx context.Context, id string, status string, previousStatus string) (*model.Dashboard, error)

	// Dashboard Widget CRUD
	AddWidgetToDashboard(ctx context.Context, widget *model.DashboardWidget) (*model.DashboardWidget, error)
	UpdateDashboardWidget(ctx context.Context, id string, update *DashboardWidgetUpdate) (*model.DashboardWidget, error)
	RemoveDashboardWidget(ctx context.Context, id string) error
	GetDashboardWidget(ctx context.Context, id string) (*model.DashboardWidget, error)
	GetDashboardWidgets(ctx context.Context, dashboardID string, version string) ([]*model.DashboardWidget, error)
	CopyWidgetsToDraft(ctx context.Context, dashboardID string) error
	PromoteDraftToPublished(ctx context.Context, dashboardID string) error
	DeleteWidgetsByVersion(ctx context.Context, dashboardID string, version string) error

	// History operations
	SaveToHistory(ctx context.Context, dashboardID string, publishedBy string) error
	GetHistory(ctx context.Context, dashboardID string) ([]*model.DashboardHistory, error)
}

// DashboardUpdate represents fields that can be updated for a dashboard
type DashboardUpdate struct {
	Name        *string
	Description *string
}

// DashboardWidgetUpdate represents fields that can be updated for a dashboard widget
type DashboardWidgetUpdate struct {
	ConfigOverrides map[string]interface{}
	Layout          map[string]interface{}
	DisplayMode     *string
	QueryOverrides  map[string]interface{}
	SortOrder       *int
}

// MongoDashboardRepository implements DashboardRepository using MongoDB
type MongoDashboardRepository struct {
	dashboardCollection        *mongo.Collection
	dashboardWidgetCollection  *mongo.Collection
	dashboardHistoryCollection *mongo.Collection
	libraryWidgetCollection    *mongo.Collection
}

// NewMongoDashboardRepository creates a new MongoDashboardRepository
func NewMongoDashboardRepository(db *mongo.Database) *MongoDashboardRepository {
	return &MongoDashboardRepository{
		dashboardCollection:        db.Collection("dashboards"),
		dashboardWidgetCollection:  db.Collection("dashboard_widgets"),
		dashboardHistoryCollection: db.Collection("dashboard_history"),
		libraryWidgetCollection:    db.Collection("library_widgets"),
	}
}

// ============================================
// Dashboard CRUD Operations
// ============================================

func (r *MongoDashboardRepository) CreateDashboard(ctx context.Context, dashboard *model.Dashboard) (*model.Dashboard, error) {
	dashboard.ID = primitive.NewObjectID().Hex()
	dashboard.Status = model.StatusDraft
	dashboard.CreatedAt = time.Now()
	dashboard.UpdatedAt = time.Now()

	_, err := r.dashboardCollection.InsertOne(ctx, dashboard)
	if err != nil {
		return nil, err
	}
	return dashboard, nil
}

func (r *MongoDashboardRepository) GetDashboard(ctx context.Context, id string) (*model.Dashboard, error) {
	var result model.Dashboard
	err := r.dashboardCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (r *MongoDashboardRepository) GetDashboards(ctx context.Context) ([]*model.Dashboard, error) {
	// Exclude trashed dashboards by default
	cursor, err := r.dashboardCollection.Find(ctx, bson.M{"status": bson.M{"$ne": model.StatusTrashed}})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []*model.Dashboard
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	return results, nil
}

func (r *MongoDashboardRepository) UpdateDashboard(ctx context.Context, id string, update *DashboardUpdate) (*model.Dashboard, error) {
	// Get current dashboard to check status
	dashboard, err := r.GetDashboard(ctx, id)
	if err != nil {
		return nil, err
	}
	if dashboard == nil {
		return nil, ErrDashboardNotFound
	}

	updateDoc := bson.M{"$set": bson.M{"updated_at": time.Now()}}
	setFields := updateDoc["$set"].(bson.M)

	// If in changed status, update draft_data; otherwise update main fields
	if dashboard.Status == model.StatusChanged {
		if update.Name != nil {
			setFields["draft_data.name"] = *update.Name
		}
		if update.Description != nil {
			setFields["draft_data.description"] = *update.Description
		}
	} else {
		if update.Name != nil {
			setFields["name"] = *update.Name
		}
		if update.Description != nil {
			setFields["description"] = *update.Description
		}
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var result model.Dashboard
	err = r.dashboardCollection.FindOneAndUpdate(ctx, bson.M{"_id": id}, updateDoc, opts).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrDashboardNotFound
		}
		return nil, err
	}
	return &result, nil
}

func (r *MongoDashboardRepository) UpdateDashboardStatus(ctx context.Context, id string, status string, previousStatus string) (*model.Dashboard, error) {
	updateDoc := bson.M{
		"$set": bson.M{
			"status":     status,
			"updated_at": time.Now(),
		},
	}
	if previousStatus != "" {
		updateDoc["$set"].(bson.M)["previous_status"] = previousStatus
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var result model.Dashboard
	err := r.dashboardCollection.FindOneAndUpdate(ctx, bson.M{"_id": id}, updateDoc, opts).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrDashboardNotFound
		}
		return nil, err
	}
	return &result, nil
}

// ============================================
// Dashboard Widget Operations
// ============================================

func (r *MongoDashboardRepository) AddWidgetToDashboard(ctx context.Context, widget *model.DashboardWidget) (*model.DashboardWidget, error) {
	widget.ID = primitive.NewObjectID().Hex()
	widget.CreatedAt = time.Now()
	widget.UpdatedAt = time.Now()

	_, err := r.dashboardWidgetCollection.InsertOne(ctx, widget)
	if err != nil {
		return nil, err
	}
	return widget, nil
}

func (r *MongoDashboardRepository) UpdateDashboardWidget(ctx context.Context, id string, update *DashboardWidgetUpdate) (*model.DashboardWidget, error) {
	updateDoc := bson.M{"$set": bson.M{"updated_at": time.Now()}}
	setFields := updateDoc["$set"].(bson.M)

	if update.ConfigOverrides != nil {
		setFields["config_overrides"] = update.ConfigOverrides
	}
	if update.Layout != nil {
		setFields["layout"] = update.Layout
	}
	if update.DisplayMode != nil {
		setFields["display_mode"] = *update.DisplayMode
	}
	if update.QueryOverrides != nil {
		setFields["query_overrides"] = update.QueryOverrides
	}
	if update.SortOrder != nil {
		setFields["sort_order"] = *update.SortOrder
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var result model.DashboardWidget
	err := r.dashboardWidgetCollection.FindOneAndUpdate(ctx, bson.M{"_id": id}, updateDoc, opts).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrWidgetNotFound
		}
		return nil, err
	}
	return &result, nil
}

func (r *MongoDashboardRepository) RemoveDashboardWidget(ctx context.Context, id string) error {
	result, err := r.dashboardWidgetCollection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return ErrWidgetNotFound
	}
	return nil
}

func (r *MongoDashboardRepository) GetDashboardWidget(ctx context.Context, id string) (*model.DashboardWidget, error) {
	var result model.DashboardWidget
	err := r.dashboardWidgetCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (r *MongoDashboardRepository) GetDashboardWidgets(ctx context.Context, dashboardID string, version string) ([]*model.DashboardWidget, error) {
	filter := bson.M{"dashboard_id": dashboardID}
	if version != "" {
		filter["version"] = version
	}

	cursor, err := r.dashboardWidgetCollection.Find(ctx, filter, options.Find().SetSort(bson.M{"sort_order": 1}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []*model.DashboardWidget
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	return results, nil
}

func (r *MongoDashboardRepository) CopyWidgetsToDraft(ctx context.Context, dashboardID string) error {
	// Get all published widgets
	widgets, err := r.GetDashboardWidgets(ctx, dashboardID, "published")
	if err != nil {
		return err
	}

	if len(widgets) == 0 {
		return nil
	}

	// Create draft copies using batch insert
	now := time.Now()
	docs := make([]interface{}, len(widgets))
	for i, widget := range widgets {
		draftWidget := *widget
		draftWidget.ID = primitive.NewObjectID().Hex()
		draftWidget.Version = "draft"
		draftWidget.CreatedAt = now
		draftWidget.UpdatedAt = now
		docs[i] = draftWidget
	}

	_, err = r.dashboardWidgetCollection.InsertMany(ctx, docs)
	return err
}

func (r *MongoDashboardRepository) PromoteDraftToPublished(ctx context.Context, dashboardID string) error {
	_, err := r.dashboardWidgetCollection.UpdateMany(
		ctx,
		bson.M{"dashboard_id": dashboardID, "version": "draft"},
		bson.M{"$set": bson.M{"version": "published", "updated_at": time.Now()}},
	)
	return err
}

func (r *MongoDashboardRepository) DeleteWidgetsByVersion(ctx context.Context, dashboardID string, version string) error {
	_, err := r.dashboardWidgetCollection.DeleteMany(ctx, bson.M{"dashboard_id": dashboardID, "version": version})
	return err
}

// ============================================
// History Operations
// ============================================

func (r *MongoDashboardRepository) SaveToHistory(ctx context.Context, dashboardID string, publishedBy string) error {
	// Get current dashboard
	dashboard, err := r.GetDashboard(ctx, dashboardID)
	if err != nil || dashboard == nil {
		return ErrDashboardNotFound
	}

	// Get published widgets
	widgets, err := r.GetDashboardWidgets(ctx, dashboardID, "published")
	if err != nil {
		return err
	}

	// Get next version number
	var lastHistory model.DashboardHistory
	opts := options.FindOne().SetSort(bson.M{"version": -1})
	err = r.dashboardHistoryCollection.FindOne(ctx, bson.M{"dashboard_id": dashboardID}, opts).Decode(&lastHistory)
	nextVersion := 1
	if err == nil {
		nextVersion = lastHistory.Version + 1
	}

	// Create history entry
	widgetsCopy := make([]model.DashboardWidget, len(widgets))
	for i, w := range widgets {
		widgetsCopy[i] = *w
	}

	history := &model.DashboardHistory{
		ID:          primitive.NewObjectID().Hex(),
		DashboardID: dashboardID,
		Version:     nextVersion,
		Snapshot: model.DashboardSnapshot{
			Dashboard: *dashboard,
			Widgets:   widgetsCopy,
		},
		PublishedAt: time.Now(),
		PublishedBy: publishedBy,
	}

	_, err = r.dashboardHistoryCollection.InsertOne(ctx, history)
	return err
}

func (r *MongoDashboardRepository) GetHistory(ctx context.Context, dashboardID string) ([]*model.DashboardHistory, error) {
	cursor, err := r.dashboardHistoryCollection.Find(
		ctx,
		bson.M{"dashboard_id": dashboardID},
		options.Find().SetSort(bson.M{"version": -1}),
	)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []*model.DashboardHistory
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	return results, nil
}
