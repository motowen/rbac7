package service

import (
	"context"
	"errors"
	"fmt"
	"rbac7/internal/abac/model"
	"rbac7/internal/abac/policy"
	"rbac7/internal/abac/repository"
	"time"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrBadRequest   = errors.New("bad request")
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict: record already exists")
)

// ABACService defines all operations for the ABAC service
type ABACService interface {
	// Access Check
	CheckAccess(ctx context.Context, req model.CheckAccessReq) (*model.CheckAccessResponse, error)
	BatchCheckAccess(ctx context.Context, req model.BatchCheckAccessReq) (*model.BatchCheckAccessResponse, error)

	// Subject CRUD
	CreateSubject(ctx context.Context, callerID string, req model.CreateSubjectReq) error
	GetSubject(ctx context.Context, userID string) (*model.Subject, error)
	UpdateSubject(ctx context.Context, callerID string, req model.UpdateSubjectReq) error
	DeleteSubject(ctx context.Context, callerID string, userID string) error

	// Group Operations
	AddSubjectToGroup(ctx context.Context, callerID string, req model.AddSubjectToGroupReq) error
	RemoveSubjectFromGroup(ctx context.Context, callerID string, req model.RemoveSubjectFromGroupReq) error

	// Org Operations
	UpsertOrgMembership(ctx context.Context, callerID string, req model.UpsertOrgMembershipReq) error
	RemoveOrgMembership(ctx context.Context, callerID string, req model.RemoveOrgMembershipReq) error

	// Policy Rule Management
	CreatePolicyRule(ctx context.Context, callerID string, req model.CreatePolicyRuleReq) (*model.PolicyRule, error)
	UpdatePolicyRule(ctx context.Context, callerID string, req model.UpdatePolicyRuleReq) error
	DeletePolicyRule(ctx context.Context, callerID string, ruleID string) error
	ListPolicyRules(ctx context.Context, filter model.PolicyRuleFilter) ([]*model.PolicyRule, error)

	// Attribute Definition Management
	CreateAttributeDefinition(ctx context.Context, callerID string, req model.CreateAttributeDefinitionReq) error
	ListAttributeDefinitions(ctx context.Context, scope, resourceType string) ([]*model.AttributeDefinition, error)
	DeleteAttributeDefinition(ctx context.Context, callerID string, key, scope string) error
}

// Service implements ABACService
type Service struct {
	SubjectRepo repository.ABACRepository
	PolicyRepo  repository.PolicyRepository
	Engine      *policy.Engine
}

// NewService creates a new ABAC service
func NewService(subjectRepo repository.ABACRepository, policyRepo repository.PolicyRepository) *Service {
	engine := policy.NewEngine(policyRepo)
	return &Service{
		SubjectRepo: subjectRepo,
		PolicyRepo:  policyRepo,
		Engine:      engine,
	}
}

// --- Access Check ---

// CheckAccess checks if a subject can perform an action on a resource
func (s *Service) CheckAccess(ctx context.Context, req model.CheckAccessReq) (*model.CheckAccessResponse, error) {
	// Get subject from DB
	subject, err := s.SubjectRepo.GetSubject(ctx, req.SubjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject: %w", err)
	}
	if subject == nil {
		return &model.CheckAccessResponse{
			Allowed: false,
			Reason:  "subject not found",
		}, nil
	}

	// Delegate to policy engine
	return s.Engine.CheckAccess(ctx, subject, &req.Resource, req.Action)
}

// BatchCheckAccess checks access for multiple resources
func (s *Service) BatchCheckAccess(ctx context.Context, req model.BatchCheckAccessReq) (*model.BatchCheckAccessResponse, error) {
	// Get subject once
	subject, err := s.SubjectRepo.GetSubject(ctx, req.SubjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject: %w", err)
	}

	results := make(map[string]model.CheckAccessResponse, len(req.Resources))

	if subject == nil {
		for _, res := range req.Resources {
			results[res.ResourceID] = model.CheckAccessResponse{
				Allowed: false,
				Reason:  "subject not found",
			}
		}
		return &model.BatchCheckAccessResponse{Results: results}, nil
	}

	for _, res := range req.Resources {
		resCopy := res // avoid closure issue
		resp, err := s.Engine.CheckAccess(ctx, subject, &resCopy, req.Action)
		if err != nil {
			return nil, err
		}
		results[res.ResourceID] = *resp
	}

	return &model.BatchCheckAccessResponse{Results: results}, nil
}

// --- Subject CRUD ---

// CreateSubject creates a new subject
func (s *Service) CreateSubject(ctx context.Context, callerID string, req model.CreateSubjectReq) error {
	subject := &model.Subject{
		UserID:           req.UserID,
		Role:             req.Role,
		Status:           req.Status,
		SensitivityLevel: req.SensitivityLevel,
		Orgs:             req.Orgs,
		GroupIDs:         req.GroupIDs,
		CustomAttrs:      req.CustomAttrs,
		CreatedBy:        callerID,
		UpdatedBy:        callerID,
	}
	if subject.Orgs == nil {
		subject.Orgs = []model.OrgMembership{}
	}
	if subject.GroupIDs == nil {
		subject.GroupIDs = []string{}
	}
	if subject.CustomAttrs == nil {
		subject.CustomAttrs = []model.CustomAttr{}
	}

	err := s.SubjectRepo.CreateSubject(ctx, subject)
	if errors.Is(err, repository.ErrDuplicate) {
		return ErrConflict
	}
	return err
}

// GetSubject retrieves a subject by user_id
func (s *Service) GetSubject(ctx context.Context, userID string) (*model.Subject, error) {
	subject, err := s.SubjectRepo.GetSubject(ctx, userID)
	if err != nil {
		return nil, err
	}
	if subject == nil {
		return nil, ErrNotFound
	}
	return subject, nil
}

// UpdateSubject updates an existing subject
func (s *Service) UpdateSubject(ctx context.Context, callerID string, req model.UpdateSubjectReq) error {
	// Get existing subject
	existing, err := s.SubjectRepo.GetSubject(ctx, req.UserID)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrNotFound
	}

	// Apply updates
	if req.Role != nil {
		existing.Role = *req.Role
	}
	if req.Status != nil {
		existing.Status = *req.Status
	}
	if req.SensitivityLevel != nil {
		existing.SensitivityLevel = *req.SensitivityLevel
	}
	if req.Orgs != nil {
		existing.Orgs = req.Orgs
	}
	if req.GroupIDs != nil {
		existing.GroupIDs = req.GroupIDs
	}
	if req.CustomAttrs != nil {
		existing.CustomAttrs = req.CustomAttrs
	}
	existing.UpdatedBy = callerID

	err = s.SubjectRepo.UpdateSubject(ctx, existing)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// DeleteSubject soft-deletes a subject
func (s *Service) DeleteSubject(ctx context.Context, callerID string, userID string) error {
	err := s.SubjectRepo.DeleteSubject(ctx, userID, callerID)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// --- Group Operations ---

// AddSubjectToGroup adds a subject to a group
func (s *Service) AddSubjectToGroup(ctx context.Context, callerID string, req model.AddSubjectToGroupReq) error {
	err := s.SubjectRepo.AddGroupToSubject(ctx, req.UserID, req.GroupID)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// RemoveSubjectFromGroup removes a subject from a group
func (s *Service) RemoveSubjectFromGroup(ctx context.Context, callerID string, req model.RemoveSubjectFromGroupReq) error {
	err := s.SubjectRepo.RemoveGroupFromSubject(ctx, req.UserID, req.GroupID)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// --- Org Operations ---

// UpsertOrgMembership adds or updates an org membership
func (s *Service) UpsertOrgMembership(ctx context.Context, callerID string, req model.UpsertOrgMembershipReq) error {
	err := s.SubjectRepo.UpsertOrgMembership(ctx, req.UserID, req.Org)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// RemoveOrgMembership removes an org membership
func (s *Service) RemoveOrgMembership(ctx context.Context, callerID string, req model.RemoveOrgMembershipReq) error {
	err := s.SubjectRepo.RemoveOrgMembership(ctx, req.UserID, req.OrgID)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// --- Policy Rule Management ---

// CreatePolicyRule creates a new policy rule
func (s *Service) CreatePolicyRule(ctx context.Context, callerID string, req model.CreatePolicyRuleReq) (*model.PolicyRule, error) {
	rule := &model.PolicyRule{
		Name:         req.Name,
		Description:  req.Description,
		ResourceType: req.ResourceType,
		Action:       req.Action,
		Effect:       req.Effect,
		Priority:     req.Priority,
		Conditions:   req.Conditions,
		Enabled:      req.Enabled,
		CreatedBy:    callerID,
		UpdatedBy:    callerID,
	}

	if err := s.PolicyRepo.CreatePolicyRule(ctx, rule); err != nil {
		if errors.Is(err, repository.ErrDuplicate) {
			return nil, ErrConflict
		}
		return nil, err
	}

	return rule, nil
}

// UpdatePolicyRule updates an existing policy rule
func (s *Service) UpdatePolicyRule(ctx context.Context, callerID string, req model.UpdatePolicyRuleReq) error {
	existing, err := s.PolicyRepo.GetPolicyRule(ctx, req.ID)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrNotFound
	}

	// Apply partial updates
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = *req.Description
	}
	if req.ResourceType != nil {
		existing.ResourceType = *req.ResourceType
	}
	if req.Action != nil {
		existing.Action = *req.Action
	}
	if req.Effect != nil {
		existing.Effect = *req.Effect
	}
	if req.Priority != nil {
		existing.Priority = *req.Priority
	}
	if req.Conditions != nil {
		existing.Conditions = *req.Conditions
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	existing.UpdatedBy = callerID
	existing.UpdatedAt = time.Now()

	err = s.PolicyRepo.UpdatePolicyRule(ctx, existing)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// DeletePolicyRule deletes a policy rule
func (s *Service) DeletePolicyRule(ctx context.Context, callerID string, ruleID string) error {
	err := s.PolicyRepo.DeletePolicyRule(ctx, ruleID)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// ListPolicyRules lists policy rules with optional filtering
func (s *Service) ListPolicyRules(ctx context.Context, filter model.PolicyRuleFilter) ([]*model.PolicyRule, error) {
	return s.PolicyRepo.ListPolicyRules(ctx, filter)
}

// --- Attribute Definition Management ---

// CreateAttributeDefinition creates a new attribute definition
func (s *Service) CreateAttributeDefinition(ctx context.Context, callerID string, req model.CreateAttributeDefinitionReq) error {
	def := &model.AttributeDefinition{
		Key:           req.Key,
		Scope:         req.Scope,
		ResourceType:  req.ResourceType,
		Type:          req.Type,
		ManagedBy:     req.ManagedBy,
		Operators:     req.Operators,
		AllowedValues: req.AllowedValues,
		CreatedBy:     callerID,
	}

	err := s.PolicyRepo.CreateAttributeDefinition(ctx, def)
	if errors.Is(err, repository.ErrDuplicate) {
		return ErrConflict
	}
	return err
}

// ListAttributeDefinitions lists attribute definitions
func (s *Service) ListAttributeDefinitions(ctx context.Context, scope, resourceType string) ([]*model.AttributeDefinition, error) {
	return s.PolicyRepo.ListAttributeDefinitions(ctx, scope, resourceType)
}

// DeleteAttributeDefinition deletes an attribute definition
func (s *Service) DeleteAttributeDefinition(ctx context.Context, callerID string, key, scope string) error {
	err := s.PolicyRepo.DeleteAttributeDefinition(ctx, key, scope)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	return err
}
