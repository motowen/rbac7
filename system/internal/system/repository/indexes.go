package repository

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// IndexEnsurer defines the interface for ensuring indexes
type IndexEnsurer interface {
	EnsureIndexes(ctx context.Context) error
}

// ============================================
// Dashboard Repository Indexes
// ============================================

// EnsureIndexes creates all necessary indexes for dashboard-related collections
func (r *MongoDashboardRepository) EnsureIndexes(ctx context.Context) error {
	// 1. Dashboards collection indexes
	dashboardIndexes := []mongo.IndexModel{
		// Index on status for filtering (GetDashboards excludes trashed)
		{
			Keys:    bson.D{{Key: "status", Value: 1}},
			Options: options.Index().SetName("idx_status"),
		},
		// Index on created_by for potential user queries
		{
			Keys:    bson.D{{Key: "created_by", Value: 1}},
			Options: options.Index().SetName("idx_created_by"),
		},
	}
	if _, err := r.dashboardCollection.Indexes().CreateMany(ctx, dashboardIndexes); err != nil {
		return err
	}

	// 2. Dashboard widgets collection indexes
	widgetIndexes := []mongo.IndexModel{
		// Compound index on dashboard_id + version (most common query pattern)
		{
			Keys: bson.D{
				{Key: "dashboard_id", Value: 1},
				{Key: "version", Value: 1},
			},
			Options: options.Index().SetName("idx_dashboard_version"),
		},
		// Index on sort_order for ordering
		{
			Keys: bson.D{
				{Key: "dashboard_id", Value: 1},
				{Key: "sort_order", Value: 1},
			},
			Options: options.Index().SetName("idx_dashboard_sort"),
		},
		// Index on library_widget_id for reverse lookups
		{
			Keys:    bson.D{{Key: "library_widget_id", Value: 1}},
			Options: options.Index().SetName("idx_library_widget_id"),
		},
	}
	if _, err := r.dashboardWidgetCollection.Indexes().CreateMany(ctx, widgetIndexes); err != nil {
		return err
	}

	// 3. Dashboard locks collection indexes
	lockIndexes := []mongo.IndexModel{
		// Unique index on dashboard_id (one lock per dashboard)
		{
			Keys:    bson.D{{Key: "dashboard_id", Value: 1}},
			Options: options.Index().SetUnique(true).SetName("uniq_dashboard_lock"),
		},
		// Index on expires_at for lock expiration queries
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetName("idx_expires_at"),
		},
	}
	if _, err := r.dashboardLockCollection.Indexes().CreateMany(ctx, lockIndexes); err != nil {
		return err
	}

	// 4. Dashboard history collection indexes
	historyIndexes := []mongo.IndexModel{
		// Compound index on dashboard_id + version for queries and ordering
		{
			Keys: bson.D{
				{Key: "dashboard_id", Value: 1},
				{Key: "version", Value: -1},
			},
			Options: options.Index().SetName("idx_dashboard_history"),
		},
	}
	if _, err := r.dashboardHistoryCollection.Indexes().CreateMany(ctx, historyIndexes); err != nil {
		return err
	}

	return nil
}

// ============================================
// Widget Repository Indexes
// ============================================

// EnsureIndexes creates all necessary indexes for library_widgets collection
func (r *MongoWidgetRepository) EnsureIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		// Index on status for filtering
		{
			Keys:    bson.D{{Key: "status", Value: 1}},
			Options: options.Index().SetName("idx_status"),
		},
		// Index on type for filtering by widget type
		{
			Keys:    bson.D{{Key: "type", Value: 1}},
			Options: options.Index().SetName("idx_type"),
		},
		// Multikey index on tags for tag-based queries
		{
			Keys:    bson.D{{Key: "tags", Value: 1}},
			Options: options.Index().SetName("idx_tags"),
		},
		// Compound index for type + status filtering
		{
			Keys: bson.D{
				{Key: "type", Value: 1},
				{Key: "status", Value: 1},
			},
			Options: options.Index().SetName("idx_type_status"),
		},
	}

	_, err := r.libraryWidgetCollection.Indexes().CreateMany(ctx, indexes)
	return err
}

// ============================================
// System Repository Indexes
// ============================================

// EnsureIndexes creates all necessary indexes for system collection
func (r *MongoSystemRepository) EnsureIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		// Unique index on namespace (primary lookup key)
		{
			Keys:    bson.D{{Key: "namespace", Value: 1}},
			Options: options.Index().SetUnique(true).SetName("uniq_namespace"),
		},
	}

	_, err := r.collection.Indexes().CreateMany(ctx, indexes)
	return err
}
