package natshandler

import (
	"context"
	"strings"

	"rbac7/internal/rbac/policy"
	"rbac7/internal/rbac/repository"
)

// NATSRBACChecker performs fine-grained RBAC permission checks for NATS handlers.
// This is the "細粒度" layer of the dual-layer approach, equivalent to
// the HTTP RBACMiddleware but called explicitly from each NATS handler.
type NATSRBACChecker struct {
	policyEngine *policy.Engine
	repo         repository.RBACRepository
}

// NewNATSRBACChecker creates a new RBAC checker for NATS handlers.
func NewNATSRBACChecker(engine *policy.Engine, repo repository.RBACRepository) *NATSRBACChecker {
	return &NATSRBACChecker{
		policyEngine: engine,
		repo:         repo,
	}
}

// CheckOperationPermission checks if the caller has permission to perform the given operation.
// This mirrors the HTTP RBAC middleware's permission check logic.
func (m *NATSRBACChecker) CheckOperationPermission(
	ctx context.Context,
	callerID string,
	entity string,
	operation string,
	namespace string,
	resourceID string,
	resourceType string,
	parentResourceID string,
	role string,
) (bool, error) {
	opReq := policy.OperationRequest{
		CallerID:         callerID,
		Entity:           entity,
		Operation:        operation,
		Namespace:        strings.ToUpper(strings.TrimSpace(namespace)),
		ResourceID:       resourceID,
		ResourceType:     resourceType,
		ParentResourceID: parentResourceID,
		Role:             role,
	}

	return m.policyEngine.CheckOperationPermission(ctx, m.repo, &opReq)
}
