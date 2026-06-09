package store

import (
	"time"

	"litewaf-api/internal/model"
)

const summaryTrendBucketCount = 24

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
		RequestTrend:      []model.TimeSeriesPoint{},
		BlockedTrend:      []model.TimeSeriesPoint{},
		WAFMatchTrend:     []model.TimeSeriesPoint{},
	}
}

func summaryTrendRange(filter model.ObservabilitySummaryFilter) (time.Time, time.Time) {
	until := filter.Until
	if until.IsZero() {
		until = time.Now().UTC()
	}
	until = until.UTC().Truncate(time.Hour)
	start := until.Add(-time.Duration(summaryTrendBucketCount-1) * time.Hour)
	return start, until.Add(time.Hour)
}

func newSummaryTrendBuckets(start time.Time) []int64 {
	return make([]int64, summaryTrendBucketCount)
}

func addSummaryTrendBucket(buckets []int64, start time.Time, value time.Time, count int64) {
	if value.IsZero() {
		return
	}
	index := int(value.UTC().Truncate(time.Hour).Sub(start) / time.Hour)
	if index < 0 || index >= len(buckets) {
		return
	}
	buckets[index] += count
}

func summaryTrendPoints(start time.Time, buckets []int64) []model.TimeSeriesPoint {
	points := make([]model.TimeSeriesPoint, 0, len(buckets))
	for index, count := range buckets {
		points = append(points, model.TimeSeriesPoint{
			Time:  start.Add(time.Duration(index) * time.Hour).Format(time.RFC3339),
			Value: count,
		})
	}
	return points
}
