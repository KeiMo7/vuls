package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/future-architect/vuls/models"
)

// FormatDedupJSON formats a cross-host CVE deduplication summary as JSON.
func FormatDedupJSON(summary models.DedupSummary) (string, error) {
	if summary.Cves == nil {
		summary.Cves = []models.DedupedCve{}
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal deduplication summary: %w", err)
	}
	return string(data) + "\n", nil
}
