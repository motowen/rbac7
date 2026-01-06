package model

// BatchUpsertResult represents the result of a batch upsert operation
type BatchUpsertResult struct {
	SuccessCount int              `json:"success_count"`
	FailedCount  int              `json:"failed_count"`
	FailedUsers  []FailedUserInfo `json:"failed_users,omitempty"`
}

// FailedUserInfo contains information about a failed user operation
type FailedUserInfo struct {
	UserID string `json:"user_id"`
	Reason string `json:"reason"`
}
