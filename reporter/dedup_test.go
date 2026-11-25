package reporter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/future-architect/vuls/models"
)

func fixedDedupSummary() models.DedupSummary {
	return models.DedupSummary{
		ScannedServers: 3,
		SkippedServers: 1,
		SkippedCves:    2,
		Cves: []models.DedupedCve{{
			CveID:            "CVE-2026-0001",
			Severity:         "CRITICAL",
			Cvss40Score:      9.8,
			Cvss3Score:       9.1,
			Cvss2Score:       7.5,
			HostCount:        2,
			AffectedServers:  []string{"host-a", "host-b"},
			AffectedFamilies: []string{"debian", "ubuntu"},
			Occurrences: []models.Occurrence{{
				Server:      "host-a",
				Family:      "ubuntu",
				Release:     "24.04",
				Package:     "curl",
				FixedIn:     "8.0",
				NotFixedYet: false,
				FixState:    "fixed",
			}},
			SourceTypes:     []string{"nvd"},
			SourceLinks:     []string{"https://example.test/cve"},
			KEVTypes:        []string{"cisa", "enisa"},
			ExploitCount:    2,
			MetasploitCount: 1,
			AdvisoryIDs:     []string{"ADV-1"},
			AllUnfixed:      false,
			VulnType:        "remote",
		}},
	}
}

func TestFormatDedupJSONMatchesFixture(t *testing.T) {
	summary := fixedDedupSummary()
	got, err := FormatDedupJSON(summary)
	if err != nil {
		t.Fatal(err)
	}

	fixturePath := filepath.Join("testdata", "dedup_expected.json")
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("JSON does not match %s.\n--- got ---\n%s\n--- want ---\n%s", fixturePath, got, want)
	}
	if got[len(got)-1] != '\n' || got[len(got)-2] == '\n' {
		t.Fatal("output must end with exactly one newline")
	}
}

func TestFormatDedupJSONEmptyCvesArray(t *testing.T) {
	got, err := FormatDedupJSON(models.DedupSummary{})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"scannedServers\": 0,\n  \"skippedServers\": 0,\n  \"skippedCves\": 0,\n  \"cves\": []\n}\n"
	if got != want {
		t.Fatalf("empty summary JSON = %q, want %q", got, want)
	}
}
