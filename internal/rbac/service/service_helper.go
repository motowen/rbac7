package service

import "rbac7/internal/rbac/model"

func (s *Service) validateRequest(callerID string, req model.SystemOwnerUpsertRequest) error {
	if err := s.validateCallerAndNamespace(callerID, req.Namespace); err != nil {
		return err
	}
	if req.UserID == "" {
		return ErrBadRequest
	}
	return nil
}

func (s *Service) validateCallerAndNamespace(callerID, namespace string) error {
	if callerID == "" {
		return ErrUnauthorized
	}
	if namespace == "" {
		return ErrInvalidNamespace
	}
	return nil
}
