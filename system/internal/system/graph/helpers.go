package graph

import (
	model1 "system/internal/system/graph/model"
	"system/internal/system/model"
)

// mapStatusToGQL maps internal status string to GraphQL EntityStatus enum
func mapStatusToGQL(status string) model1.EntityStatus {
	switch status {
	case model.StatusDraft:
		return model1.EntityStatusDraft
	case model.StatusPublished:
		return model1.EntityStatusPublished
	case model.StatusChanged:
		return model1.EntityStatusChanged
	case model.StatusTrashed:
		return model1.EntityStatusTrashed
	default:
		return model1.EntityStatusDraft
	}
}

func convertDatasourceInputsToModel(inputs []*model1.DatasourceInput) []model.Datasource {
	if inputs == nil {
		return nil
	}
	result := make([]model.Datasource, len(inputs))
	for i, input := range inputs {
		result[i] = model.Datasource{
			ID:     input.ID,
			Name:   input.Name,
			Type:   input.Type,
			Config: input.Config,
		}
		if input.Description != nil {
			result[i].Description = *input.Description
		}
	}
	return result
}
