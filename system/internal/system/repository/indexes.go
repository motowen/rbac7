package repository

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ============================================
// Dashboard indexes
// ============================================

func (r *MongoDashboardRepository) EnsureIndexes(ctx context.Context) error {
	// 1. Dashboards collection indexes
	dashboardIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "status", Value: 1}},
			Options: options.Index().SetName("idx_status"),
		},
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
		{
			Keys: bson.D{
				{Key: "dashboard_id", Value: 1},
				{Key: "version", Value: 1},
			},
			Options: options.Index().SetName("idx_dashboard_version"),
		},
		{
			Keys: bson.D{
				{Key: "dashboard_id", Value: 1},
				{Key: "sort_order", Value: 1},
			},
			Options: options.Index().SetName("idx_dashboard_sort"),
		},
		{
			Keys:    bson.D{{Key: "library_widget_id", Value: 1}},
			Options: options.Index().SetName("idx_library_widget_id"),
		},
	}
	if _, err := r.dashboardWidgetCollection.Indexes().CreateMany(ctx, widgetIndexes); err != nil {
		return err
	}

	// 3. Dashboard history collection indexes
	historyIndexes := []mongo.IndexModel{
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
// Widget indexes
// ============================================

func (r *MongoWidgetRepository) EnsureIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "status", Value: 1}},
			Options: options.Index().SetName("idx_status"),
		},
		{
			Keys:    bson.D{{Key: "type", Value: 1}},
			Options: options.Index().SetName("idx_type"),
		},
		{
			Keys:    bson.D{{Key: "tags", Value: 1}},
			Options: options.Index().SetName("idx_tags"),
		},
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
// System indexes
// ============================================

func (r *MongoSystemRepository) EnsureIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "namespace", Value: 1}},
			Options: options.Index().SetUnique(true).SetName("uniq_namespace"),
		},
	}

	_, err := r.collection.Indexes().CreateMany(ctx, indexes)
	return err
}
