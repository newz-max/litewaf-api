package store

import (
	"strings"

	"litewaf-api/internal/model"
)

func deniedRecordFromAccessLog(item model.AccessLog) model.DeniedRecord {
	return model.DeniedRecord{
		ID:                item.ID,
		RequestID:         item.RequestID,
		SiteID:            item.SiteID,
		ListenerPort:      item.ListenerPort,
		Scheme:            item.Scheme,
		Host:              item.Host,
		Method:            item.Method,
		URI:               item.URI,
		Status:            item.Status,
		UpstreamStatus:    item.UpstreamStatus,
		DurationMS:        item.DurationMS,
		ClientIP:          item.ClientIP,
		Disposition:       item.Disposition,
		ReasonCode:        item.ReasonCode,
		Reason:            item.Reason,
		ExplanationSource: "unclassified",
		CorrelationType:   "none",
		CreatedAt:         item.CreatedAt,
		Time:              item.Time,
	}
}

func deniedRecordWithWAFEvent(record model.DeniedRecord, event model.WAFEvent) model.DeniedRecord {
	record.ExplanationSource = "waf-event"
	record.CorrelationType = "request-id"
	record.WAFEventID = event.ID
	record.EventType = event.EventType
	record.Module = event.Module
	record.Category = event.Category
	record.RuleID = event.RuleID
	record.RuleName = event.RuleName
	record.Action = event.Action
	record.AttackType = event.AttackType
	record.Summary = event.Summary
	if record.ReasonCode == "" {
		record.ReasonCode = event.EventType
	}
	if record.Reason == "" {
		record.Reason = event.Summary
	}
	return record
}

func deniedRecordWithDynamicBan(record model.DeniedRecord, ban model.DynamicBan) model.DeniedRecord {
	record.ExplanationSource = "dynamic-ban"
	record.CorrelationType = "fallback"
	record.DynamicBanReason = ban.BanReason
	record.DynamicBanSource = ban.Source
	record.DynamicBanStatus = ban.Status
	record.DynamicBanRemainingSec = ban.BanRemainingSec
	if record.ReasonCode == "" {
		record.ReasonCode = "dynamic-ban"
	}
	if record.Reason == "" {
		record.Reason = ban.BanReason
	}
	return record
}

func accessLogMatchesDeniedFilter(item model.AccessLog, filter model.DeniedRecordFilter) bool {
	if item.Disposition != "blocked" && item.Disposition != "rejected" {
		return false
	}
	if filter.SiteID > 0 && item.SiteID != filter.SiteID {
		return false
	}
	if filter.ListenerPort > 0 && item.ListenerPort != filter.ListenerPort {
		return false
	}
	if filter.Scheme != "" && item.Scheme != filter.Scheme {
		return false
	}
	if filter.Host != "" && item.Host != filter.Host {
		return false
	}
	if filter.ClientIP != "" && item.ClientIP != filter.ClientIP {
		return false
	}
	if filter.Method != "" && item.Method != filter.Method {
		return false
	}
	if filter.URI != "" && !strings.Contains(item.URI, filter.URI) {
		return false
	}
	if filter.Status > 0 && item.Status != filter.Status {
		return false
	}
	if filter.Disposition != "" && item.Disposition != filter.Disposition {
		return false
	}
	return summaryTimeMatches(item.CreatedAt, filter.Since, filter.Until)
}

func deniedRecordMatches(item model.DeniedRecord, filter model.DeniedRecordFilter) bool {
	if filter.Module != "" && item.Module != filter.Module {
		return false
	}
	if filter.Action != "" && item.Action != filter.Action {
		return false
	}
	if filter.TriggerSource != "" && item.ExplanationSource != filter.TriggerSource {
		return false
	}
	return true
}
