package repository

import (
	"context"
	"time"

	"system/internal/system/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// WidgetRepository defines the interface for widget data access
type WidgetRepository interface {
	// Library Widget operations
	CreateLibraryWidget(ctx context.Context, widget *model.LibraryWidget) (*model.LibraryWidget, error)
	UpdateLibraryWidget(ctx context.Context, id string, update *LibraryWidgetUpdate) (*model.LibraryWidget, error)
	DeleteLibraryWidget(ctx context.Context, id string) error
	GetLibraryWidget(ctx context.Context, id string) (*model.LibraryWidget, error)
	GetLibraryWidgets(ctx context.Context) ([]*model.LibraryWidget, error)

	// Dashboard Widget operations
	CreateDashboardWidget(ctx context.Context, widget *model.DashboardWidget) (*model.DashboardWidget, error)
	UpdateDashboardWidget(ctx context.Context, id string, layout *model.DashboardWidgetLayout) (*model.DashboardWidget, error)
	DeleteDashboardWidget(ctx context.Context, id string) error
	GetDashboardWidget(ctx context.Context, id string) (*model.DashboardWidget, error)
	GetDashboardWidgets(ctx context.Context, dashboardID string) ([]*model.DashboardWidget, error)
}

// LibraryWidgetUpdate represents fields that can be updated
type LibraryWidgetUpdate struct {
	Name         *string
	Version      *string
	Type         *string
	TypeVersion  *string
	Schema       map[string]interface{}
	Datasource   []model.Datasource
	Status       *string
	ThumbnailURL *string
	UserConfig   map[string]interface{}
}

// MongoWidgetRepository implements WidgetRepository using MongoDB
type MongoWidgetRepository struct {
	libraryWidgetCollection   *mongo.Collection
	dashboardWidgetCollection *mongo.Collection
}

// NewMongoWidgetRepository creates a new MongoWidgetRepository
func NewMongoWidgetRepository(db *mongo.Database) *MongoWidgetRepository {
	return &MongoWidgetRepository{
		libraryWidgetCollection:   db.Collection("library_widgets"),
		dashboardWidgetCollection: db.Collection("dashboard_widgets"),
	}
}

// ============================================
// Library Widget Operations
// ============================================

func (r *MongoWidgetRepository) CreateLibraryWidget(ctx context.Context, widget *model.LibraryWidget) (*model.LibraryWidget, error) {
	widget.ID = primitive.NewObjectID().Hex()
	widget.CreatedAt = time.Now()
	widget.UpdatedAt = time.Now()

	_, err := r.libraryWidgetCollection.InsertOne(ctx, widget)
	if err != nil {
		return nil, err
	}
	return widget, nil
}

func (r *MongoWidgetRepository) UpdateLibraryWidget(ctx context.Context, id string, update *LibraryWidgetUpdate) (*model.LibraryWidget, error) {
	updateDoc := bson.M{"$set": bson.M{"updated_at": time.Now()}}
	setFields := updateDoc["$set"].(bson.M)

	if update.Name != nil {
		setFields["name"] = *update.Name
	}
	if update.Version != nil {
		setFields["version"] = *update.Version
	}
	if update.Type != nil {
		setFields["type"] = *update.Type
	}
	if update.TypeVersion != nil {
		setFields["type_version"] = *update.TypeVersion
	}
	if update.Schema != nil {
		setFields["schema"] = update.Schema
	}
	if update.Datasource != nil {
		setFields["datasource"] = update.Datasource
	}
	if update.Status != nil {
		setFields["status"] = *update.Status
	}
	if update.ThumbnailURL != nil {
		setFields["thumbnail_url"] = *update.ThumbnailURL
	}
	if update.UserConfig != nil {
		setFields["user_config"] = update.UserConfig
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var result model.LibraryWidget
	err := r.libraryWidgetCollection.FindOneAndUpdate(ctx, bson.M{"_id": id}, updateDoc, opts).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (r *MongoWidgetRepository) DeleteLibraryWidget(ctx context.Context, id string) error {
	_, err := r.libraryWidgetCollection.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func (r *MongoWidgetRepository) GetLibraryWidget(ctx context.Context, id string) (*model.LibraryWidget, error) {
	var result model.LibraryWidget
	err := r.libraryWidgetCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (r *MongoWidgetRepository) GetLibraryWidgets(ctx context.Context) ([]*model.LibraryWidget, error) {
	cursor, err := r.libraryWidgetCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []*model.LibraryWidget
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	return results, nil
}

// ============================================
// Dashboard Widget Operations
// ============================================

func (r *MongoWidgetRepository) CreateDashboardWidget(ctx context.Context, widget *model.DashboardWidget) (*model.DashboardWidget, error) {
	widget.ID = primitive.NewObjectID().Hex()
	widget.CreatedAt = time.Now()
	widget.UpdatedAt = time.Now()

	_, err := r.dashboardWidgetCollection.InsertOne(ctx, widget)
	if err != nil {
		return nil, err
	}
	return widget, nil
}

func (r *MongoWidgetRepository) UpdateDashboardWidget(ctx context.Context, id string, layout *model.DashboardWidgetLayout) (*model.DashboardWidget, error) {
	updateDoc := bson.M{
		"$set": bson.M{
			"layout":     layout,
			"updated_at": time.Now(),
		},
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var result model.DashboardWidget
	err := r.dashboardWidgetCollection.FindOneAndUpdate(ctx, bson.M{"_id": id}, updateDoc, opts).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (r *MongoWidgetRepository) DeleteDashboardWidget(ctx context.Context, id string) error {
	_, err := r.dashboardWidgetCollection.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func (r *MongoWidgetRepository) GetDashboardWidget(ctx context.Context, id string) (*model.DashboardWidget, error) {
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

func (r *MongoWidgetRepository) GetDashboardWidgets(ctx context.Context, dashboardID string) ([]*model.DashboardWidget, error) {
	cursor, err := r.dashboardWidgetCollection.Find(ctx, bson.M{"dashboard_id": dashboardID})
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
