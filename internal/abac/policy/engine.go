package policy

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"rbac7/internal/abac/model"
	"rbac7/internal/abac/repository"
	"sort"

	"github.com/open-policy-agent/opa/v1/rego"
)

//go:embed policies/abac.rego
var policyFS embed.FS

// Engine is the ABAC policy engine using embedded OPA for access control evaluation
type Engine struct {
	policyRepo repository.PolicyRepository
	query      rego.PreparedEvalQuery
}

// NewEngine creates a new ABAC Policy Engine with OPA
func NewEngine(policyRepo repository.PolicyRepository) (*Engine, error) {
	policyBytes, err := policyFS.ReadFile("policies/abac.rego")
	if err != nil {
		return nil, fmt.Errorf("failed to read rego policy: %w", err)
	}

	query, err := rego.New(
		rego.Query("data.abac.allow; data.abac.reason"),
		rego.Module("abac.rego", string(policyBytes)),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	return &Engine{
		policyRepo: policyRepo,
		query:      query,
	}, nil
}

// OPAInput represents the input document passed to OPA
type OPAInput struct {
	Subject  OPASubject  `json:"subject"`
	Resource OPAResource `json:"resource"`
	Action   string      `json:"action"`
}

// OPASubject is the subject representation for OPA input
type OPASubject struct {
	UserID           string                   `json:"user_id"`
	Role             string                   `json:"role"`
	Status           string                   `json:"status"`
	SensitivityLevel string                   `json:"sensitivity_level"`
	GroupIDs         []string                 `json:"group_ids"`
	CustomAttrs      []map[string]interface{} `json:"custom_attrs"`
}

// OPAResource is the resource representation for OPA input
type OPAResource struct {
	ResourceID       string                   `json:"resource_id"`
	ResourceType     string                   `json:"resource_type"`
	ResourceParentID string                   `json:"resource_parent_id"`
	OwnerID          string                   `json:"owner_id"`
	SensitivityLevel string                   `json:"sensitivity_level"`
	Status           string                   `json:"status"`
	AllowedGroupIDs  []string                 `json:"allowed_group_ids"`
	DeniedGroupIDs   []string                 `json:"denied_group_ids"`
	ResourceGroupIDs []string                 `json:"resource_group_ids"`
	CustomAttrs      []map[string]interface{} `json:"custom_attrs"`
}

// CheckAccess evaluates whether a subject can perform an action on a resource using OPA
func (e *Engine) CheckAccess(
	ctx context.Context,
	subject *model.Subject,
	resource *model.ResourceAttrs,
	action string,
) (*model.CheckAccessResponse, error) {
	// Load applicable policy rules from DB
	rules, err := e.policyRepo.FindPolicyRules(ctx, resource.ResourceType, action)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy rules: %w", err)
	}

	// Build OPA input (includes subject, resource, action, AND rules from DB)
	input := buildOPAInput(subject, resource, action, rules)

	// Evaluate using OPA
	results, err := e.query.Eval(ctx,
		rego.EvalInput(input),
	)
	if err != nil {
		return nil, fmt.Errorf("OPA evaluation failed: %w", err)
	}

	return parseOPAResult(results)
}

// buildOPAInput converts Subject + Resource + Action + DB Rules into OPA input document
func buildOPAInput(subject *model.Subject, resource *model.ResourceAttrs, action string, rules []*model.PolicyRule) map[string]interface{} {
	// Convert subject
	subjectCustom := make([]map[string]interface{}, 0, len(subject.CustomAttrs))
	for _, attr := range subject.CustomAttrs {
		subjectCustom = append(subjectCustom, map[string]interface{}{
			"key":   attr.Key,
			"value": attr.Value,
		})
	}

	groupIDs := subject.GroupIDs
	if groupIDs == nil {
		groupIDs = []string{}
	}

	// Convert resource
	resourceCustom := make([]map[string]interface{}, 0, len(resource.CustomAttrs))
	for _, attr := range resource.CustomAttrs {
		resourceCustom = append(resourceCustom, map[string]interface{}{
			"key":   attr.Key,
			"value": attr.Value,
		})
	}

	allowedGroupIDs := resource.AllowedGroupIDs
	if allowedGroupIDs == nil {
		allowedGroupIDs = []string{}
	}
	deniedGroupIDs := resource.DeniedGroupIDs
	if deniedGroupIDs == nil {
		deniedGroupIDs = []string{}
	}
	resourceGroupIDs := resource.ResourceGroupIDs
	if resourceGroupIDs == nil {
		resourceGroupIDs = []string{}
	}

	// Convert DB rules to OPA-friendly format
	opaRules := make([]map[string]interface{}, 0, len(rules))
	for _, rule := range rules {
		condBytes, _ := json.Marshal(rule.Conditions)
		var conditions map[string]interface{}
		_ = json.Unmarshal(condBytes, &conditions)

		if conditions == nil {
			conditions = map[string]interface{}{}
		}
		if _, ok := conditions["subject"]; !ok {
			conditions["subject"] = []interface{}{}
		}
		if _, ok := conditions["resource"]; !ok {
			conditions["resource"] = []interface{}{}
		}

		opaRules = append(opaRules, map[string]interface{}{
			"name":          rule.Name,
			"resource_type": rule.ResourceType,
			"action":        rule.Action,
			"effect":        rule.Effect,
			"priority":      rule.Priority,
			"conditions":    conditions,
			"enabled":       rule.Enabled,
		})
	}

	return map[string]interface{}{
		"subject": map[string]interface{}{
			"user_id":           subject.UserID,
			"role":              subject.Role,
			"status":            subject.Status,
			"sensitivity_level": subject.SensitivityLevel,
			"group_ids":         groupIDs,
			"custom_attrs":      subjectCustom,
		},
		"resource": map[string]interface{}{
			"resource_id":        resource.ResourceID,
			"resource_type":      resource.ResourceType,
			"resource_parent_id": resource.ResourceParentID,
			"owner_id":           resource.OwnerID,
			"sensitivity_level":  resource.SensitivityLevel,
			"status":             resource.Status,
			"allowed_group_ids":  allowedGroupIDs,
			"denied_group_ids":   deniedGroupIDs,
			"resource_group_ids": resourceGroupIDs,
			"custom_attrs":       resourceCustom,
		},
		"action": action,
		"rules":  opaRules,
	}
}

// parseOPAResult extracts allow/reason from OPA evaluation result
func parseOPAResult(results rego.ResultSet) (*model.CheckAccessResponse, error) {
	if len(results) == 0 {
		return &model.CheckAccessResponse{
			Allowed: false,
			Reason:  "no OPA result",
		}, nil
	}

	allowed := false
	reason := "no matching policy rules"

	// results[0].Expressions[0] = data.abac.allow
	// results[0].Expressions[1] = data.abac.reason
	if len(results[0].Expressions) >= 1 {
		if v, ok := results[0].Expressions[0].Value.(bool); ok {
			allowed = v
		}
	}
	if len(results[0].Expressions) >= 2 {
		if v, ok := results[0].Expressions[1].Value.(string); ok {
			reason = v
		}
	}

	return &model.CheckAccessResponse{
		Allowed: allowed,
		Reason:  reason,
	}, nil
}

// SortRulesByPriority sorts rules by priority descending (utility function)
func SortRulesByPriority(rules []*model.PolicyRule) {
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})
}
