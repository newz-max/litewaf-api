package store

import "litewaf-api/internal/model"

func emptyObservabilitySummary() model.ObservabilitySummary {
	return model.ObservabilitySummary{
		AccessControl:     []model.SummaryCount{},
		IPAccessList:      []model.SummaryCount{},
		TopIPs:            []model.SummaryCount{},
		TopURIs:           []model.SummaryCount{},
		TopRules:          []model.SummaryCount{},
		AttackTypes:       []model.SummaryCount{},
		AttackProtection:  []model.SummaryCount{},
		UploadProtection:  []model.SummaryCount{},
		BotProtection:     []model.SummaryCount{},
		DynamicProtection: []model.SummaryCount{},
	}
}
