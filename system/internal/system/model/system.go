package model

import "time"

// System represents a system entity stored in MongoDB
type System struct {
	Namespace   string    `bson:"namespace"`
	Name        string    `bson:"name"`
	Description string    `bson:"description"`
	CreatedAt   time.Time `bson:"created_at"`
	UpdatedAt   time.Time `bson:"updated_at"`
}
