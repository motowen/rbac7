package model

import "time"

type SystemUserRole struct {
	UserID    string `json:"user_id" bson:"user_id"`
	UserType  string `json:"user_type" bson:"user_type"`
	Role      string `json:"role" bson:"role"`
	Scope     string `json:"scope" bson:"scope"`
	Namespace string `json:"namespace" bson:"namespace"`
}

type SystemOwnerUpsertRequest struct {
	UserID    string `json:"user_id"`
	Namespace string `json:"namespace"`
}

// ErrorResponse for consistent error handling
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// Internal Representation for Repo
type UserRole struct {
	ID        string `bson:"_id,omitempty"`
	UserID    string `bson:"user_id"`
	UserType  string `bson:"user_type"`
	Role      string `bson:"role"`
	Scope     string `bson:"scope"`
	Namespace string `bson:"namespace,omitempty"`
	// Resource Scoping
	ResourceID   string `bson:"resource_id,omitempty"`
	ResourceType string `bson:"resource_type,omitempty"`

	// Audit Fields
	CreatedAt time.Time  `bson:"created_at"`
	UpdatedAt time.Time  `bson:"updated_at"`
	DeletedAt *time.Time `bson:"deleted_at,omitempty"`
	CreatedBy string     `bson:"created_by,omitempty"`
	UpdatedBy string     `bson:"updated_by,omitempty"`
	DeletedBy string     `bson:"deleted_by,omitempty"`
}

type UserRoleFilter struct {
	UserID       string
	Namespace    string
	Role         string
	Scope        string
	ResourceID   string
	ResourceType string
}

// Resource Scope Requests
type ResourceUserRole struct {
	UserID       string `json:"user_id"`
	UserType     string `json:"user_type"`
	Role         string `json:"role"`
	Scope        string `json:"scope"` // Should be 'resource'
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
}

type ResourceOwnerUpsertRequest struct {
	UserID       string `json:"user_id"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
}
