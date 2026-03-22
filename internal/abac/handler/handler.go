package handler

import (
	"net/http"
	"rbac7/internal/abac/model"
	"rbac7/internal/abac/service"

	"github.com/labstack/echo/v4"
)

// Handler handles all ABAC HTTP requests
type Handler struct {
	Service service.ABACService
}

// NewHandler creates a new ABAC Handler
func NewHandler(svc service.ABACService) *Handler {
	return &Handler{Service: svc}
}

// --- Access Check Endpoints ---

// PostCheckAccess handles POST /api/v1/access/check
func (h *Handler) PostCheckAccess(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.CheckAccessReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	// Use callerID as subject_id if not provided
	if req.SubjectID == "" {
		req.SubjectID = callerID
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	resp, err := h.Service.CheckAccess(c.Request().Context(), req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, resp)
}

// PostBatchCheckAccess handles POST /api/v1/access/check/batch
func (h *Handler) PostBatchCheckAccess(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.BatchCheckAccessReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if req.SubjectID == "" {
		req.SubjectID = callerID
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	resp, err := h.Service.BatchCheckAccess(c.Request().Context(), req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, resp)
}

// --- Subject CRUD Endpoints ---

// PostSubject handles POST /api/v1/subjects
func (h *Handler) PostSubject(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.CreateSubjectReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	err = h.Service.CreateSubject(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusCreated, map[string]string{"status": "success"})
}

// GetSubject handles GET /api/v1/subjects/:user_id
func (h *Handler) GetSubject(c echo.Context) error {
	_, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	userID := c.Param("user_id")
	if userID == "" {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "user_id is required"},
		})
	}

	subject, err := h.Service.GetSubject(c.Request().Context(), userID)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, subject)
}

// PutSubject handles PUT /api/v1/subjects/:user_id
func (h *Handler) PutSubject(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.UpdateSubjectReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}
	req.UserID = c.Param("user_id")

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	err = h.Service.UpdateSubject(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// DeleteSubject handles DELETE /api/v1/subjects/:user_id
func (h *Handler) DeleteSubject(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	userID := c.Param("user_id")
	if userID == "" {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "user_id is required"},
		})
	}

	err = h.Service.DeleteSubject(c.Request().Context(), callerID, userID)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// --- Group Endpoints ---

// PostSubjectGroup handles POST /api/v1/subjects/:user_id/groups
func (h *Handler) PostSubjectGroup(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.AddSubjectToGroupReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}
	req.UserID = c.Param("user_id")

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	err = h.Service.AddSubjectToGroup(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// DeleteSubjectGroup handles DELETE /api/v1/subjects/:user_id/groups/:group_id
func (h *Handler) DeleteSubjectGroup(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	req := model.RemoveSubjectFromGroupReq{
		UserID:  c.Param("user_id"),
		GroupID: c.Param("group_id"),
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	err = h.Service.RemoveSubjectFromGroup(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// --- Org Endpoints ---

// PutSubjectOrg handles PUT /api/v1/subjects/:user_id/orgs
func (h *Handler) PutSubjectOrg(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.UpsertOrgMembershipReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}
	req.UserID = c.Param("user_id")

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	err = h.Service.UpsertOrgMembership(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// DeleteSubjectOrg handles DELETE /api/v1/subjects/:user_id/orgs/:org_id
func (h *Handler) DeleteSubjectOrg(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	req := model.RemoveOrgMembershipReq{
		UserID: c.Param("user_id"),
		OrgID:  c.Param("org_id"),
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	err = h.Service.RemoveOrgMembership(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// --- Policy Rule Endpoints ---

// PostPolicyRule handles POST /api/v1/policies
func (h *Handler) PostPolicyRule(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.CreatePolicyRuleReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	rule, err := h.Service.CreatePolicyRule(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusCreated, rule)
}

// PutPolicyRule handles PUT /api/v1/policies/:rule_id
func (h *Handler) PutPolicyRule(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.UpdatePolicyRuleReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}
	req.ID = c.Param("rule_id")

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	err = h.Service.UpdatePolicyRule(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// DeletePolicyRule handles DELETE /api/v1/policies/:rule_id
func (h *Handler) DeletePolicyRule(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	ruleID := c.Param("rule_id")
	if ruleID == "" {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "rule_id is required"},
		})
	}

	err = h.Service.DeletePolicyRule(c.Request().Context(), callerID, ruleID)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// GetPolicyRules handles GET /api/v1/policies
func (h *Handler) GetPolicyRules(c echo.Context) error {
	_, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	filter := model.PolicyRuleFilter{
		ResourceType: c.QueryParam("resource_type"),
		Action:       c.QueryParam("action"),
	}

	rules, err := h.Service.ListPolicyRules(c.Request().Context(), filter)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, rules)
}

// --- Attribute Definition Endpoints ---

// PostAttributeDefinition handles POST /api/v1/attributes
func (h *Handler) PostAttributeDefinition(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.CreateAttributeDefinitionReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	err = h.Service.CreateAttributeDefinition(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusCreated, map[string]string{"status": "success"})
}

// GetAttributeDefinitions handles GET /api/v1/attributes
func (h *Handler) GetAttributeDefinitions(c echo.Context) error {
	_, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	scope := c.QueryParam("scope")
	resourceType := c.QueryParam("resource_type")

	defs, err := h.Service.ListAttributeDefinitions(c.Request().Context(), scope, resourceType)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, defs)
}

// DeleteAttributeDefinition handles DELETE /api/v1/attributes/:key
func (h *Handler) DeleteAttributeDefinition(c echo.Context) error {
	callerID, err := extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	key := c.Param("key")
	scope := c.QueryParam("scope")
	if key == "" || scope == "" {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "key and scope are required"},
		})
	}

	err = h.Service.DeleteAttributeDefinition(c.Request().Context(), callerID, key, scope)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}
