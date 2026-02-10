package model

import "time"

// Entity type constants for the shared lock system
const (
	EntityTypeDashboard     = "dashboard"
	EntityTypeLibraryWidget = "library_widget"
)

// EntityLock represents a lock on any entity for concurrent editing protection
type EntityLock struct {
	EntityType string    `bson:"entity_type"`
	EntityID   string    `bson:"entity_id"`
	LockedBy   string    `bson:"locked_by"`
	LockedAt   time.Time `bson:"locked_at"`
	ExpiresAt  time.Time `bson:"expires_at"`
}
