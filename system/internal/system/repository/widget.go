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

// WidgetRepository defines the interface for widget data access (Library Widgets only)
type WidgetRepository interface {
	// Library Widget CRUD
	CreateLibraryWidget(ctx context.Context, widget *model.LibraryWidget) (*model.LibraryWidget, error)
	UpdateLibraryWidget(ctx context.Context, id string, update *LibraryWidgetUpdate) (*model.LibraryWidget, error)
	DeleteLibraryWidget(ctx context.Context, id string) error
	GetLibraryWidget(ctx context.Context, id string) (*model.LibraryWidget, error)
	GetLibraryWidgets(ctx context.Context) ([]*model.LibraryWidget, error)

	// Status operations
	UpdateLibraryWidgetStatus(ctx context.Context, id string, status string, previousStatus string) (*model.LibraryWidget, error)

	// History operations
	SaveToHistory(ctx context.Context, widgetID string, publishedBy string) error
	GetHistory(ctx context.Context, widgetID string) ([]*model.LibraryWidgetHistory, error)
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
	DisplayMode  *string
	Tags         []string
	UserConfig   map[string]interface{}
}

// MongoWidgetRepository implements WidgetRepository using MongoDB
type MongoWidgetRepository struct {
	libraryWidgetCollection *mongo.Collection
	widgetHistoryCollection *mongo.Collection
}

// NewMongoWidgetRepository creates a new MongoWidgetRepository
func NewMongoWidgetRepository(db *mongo.Database) *MongoWidgetRepository {
	return &MongoWidgetRepository{
		libraryWidgetCollection: db.Collection("library_widgets"),
		widgetHistoryCollection: db.Collection("widget_history"),
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
	if update.DisplayMode != nil {
		setFields["display_mode"] = *update.DisplayMode
	}
	if update.Tags != nil {
		setFields["tags"] = update.Tags
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
	// Exclude trashed widgets by default
	cursor, err := r.libraryWidgetCollection.Find(ctx, bson.M{"status": bson.M{"$ne": model.StatusTrashed}})
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

func (r *MongoWidgetRepository) UpdateLibraryWidgetStatus(ctx context.Context, id string, status string, previousStatus string) (*model.LibraryWidget, error) {
	updateDoc := bson.M{
		"$set": bson.M{
			"status":     status,
			"updated_at": time.Now(),
		},
	}
	if previousStatus != "" {
		updateDoc["$set"].(bson.M)["previous_status"] = previousStatus
	}
	// Set published_at when publishing
	if status == model.StatusPublished {
		now := time.Now()
		updateDoc["$set"].(bson.M)["published_at"] = now
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

func (r *MongoWidgetRepository) SaveToHistory(ctx context.Context, widgetID string, publishedBy string) error {
	// Get current widget
	widget, err := r.GetLibraryWidget(ctx, widgetID)
	if err != nil || widget == nil {
		return ErrLibraryWidgetNotFound
	}

	// Get next version number
	var lastHistory model.LibraryWidgetHistory
	opts := options.FindOne().SetSort(bson.M{"version": -1})
	err = r.widgetHistoryCollection.FindOne(ctx, bson.M{"widget_id": widgetID}, opts).Decode(&lastHistory)
	nextVersion := 1
	if err == nil {
		nextVersion = lastHistory.Version + 1
	}

	// Create history entry
	history := &model.LibraryWidgetHistory{
		ID:       primitive.NewObjectID().Hex(),
		WidgetID: widgetID,
		Version:  nextVersion,
		Snapshot: model.LibraryWidgetSnapshot{
			Widget: *widget,
		},
		PublishedAt: time.Now(),
		PublishedBy: publishedBy,
	}

	_, err = r.widgetHistoryCollection.InsertOne(ctx, history)
	return err
}

func (r *MongoWidgetRepository) GetHistory(ctx context.Context, widgetID string) ([]*model.LibraryWidgetHistory, error) {
	cursor, err := r.widgetHistoryCollection.Find(
		ctx,
		bson.M{"widget_id": widgetID},
		options.Find().SetSort(bson.M{"version": -1}),
	)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []*model.LibraryWidgetHistory
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	return results, nil
}
