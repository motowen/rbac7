package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RBACClient is the HTTP client for RBAC7 service
type RBACClient struct {
	baseURL    string
	httpClient *http.Client
}

// UserRole represents a user role from RBAC7
type UserRole struct {
	UserID       string `json:"user_id"`
	Role         string `json:"role"`
	Scope        string `json:"scope"`
	Namespace    string `json:"namespace"`
	ResourceID   string `json:"resource_id,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
}

// CheckPermissionRequest is the request body for permission check
type CheckPermissionRequest struct {
	Permission string `json:"permission"`
	Scope      string `json:"scope"`
	Namespace  string `json:"namespace,omitempty"`
}

// CheckPermissionResponse is the response from permission check
type CheckPermissionResponse struct {
	Allowed bool `json:"allowed"`
}

// AssignOwnerRequest is the request body for assigning system owner
type AssignOwnerRequest struct {
	UserID    string `json:"user_id"`
	Namespace string `json:"namespace"`
}

// NewRBACClient creates a new RBAC client
func NewRBACClient(baseURL string) *RBACClient {
	return &RBACClient{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		httpClient: &http.Client{},
	}
}

// CheckPermission checks if caller has the specified permission
func (c *RBACClient) CheckPermission(ctx context.Context, callerID, permission, namespace string) (bool, error) {
	reqBody := CheckPermissionRequest{
		Permission: permission,
		Scope:      "system",
		Namespace:  namespace,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/permissions/check", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-user-id", callerID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("permission check failed with status: %d", resp.StatusCode)
	}

	var result CheckPermissionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.Allowed, nil
}

// AssignSystemOwner assigns owner role to a user for a namespace
func (c *RBACClient) AssignSystemOwner(ctx context.Context, callerID, ownerID, namespace string) error {
	reqBody := AssignOwnerRequest{
		UserID:    ownerID,
		Namespace: namespace,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/user_roles/owner", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-user-id", callerID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("assign owner failed with status: %d", resp.StatusCode)
	}

	return nil
}

// GetUserRolesMe gets the caller's system roles
func (c *RBACClient) GetUserRolesMe(ctx context.Context, callerID string) ([]UserRole, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/user_roles/me?scope=system", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-user-id", callerID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user roles failed with status: %d", resp.StatusCode)
	}

	var roles []UserRole
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, err
	}

	return roles, nil
}
