package models

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"runtime/debug"
	"testing"
	"time"
)

func dedupFixtureResults() ScanResults {
	return ScanResults{
		{
			ServerName: "a",
			Family:     "ubuntu",
			Release:    "22.04",
			ScannedCves: VulnInfos{
				"CVE-1": {
					CveID:    "CVE-1",
					VulnType: "remote",
					AffectedPackages: PackageFixStatuses{
						{Name: "curl", NotFixedYet: true, FixState: "Not fixed yet"},
						{Name: "curl", FixedIn: "1.2", FixState: "fixed"},
					},
					CveContents: CveContents{
						Nvd: []CveContent{{
							Cvss40Score:    9.1,
							Cvss40Severity: "critical",
							SourceLink:     "https://nvd.example/CVE-1",
						}},
					},
					KEVs:             []KEV{{Type: CISAKEVType}},
					DistroAdvisories: DistroAdvisories{{AdvisoryID: "ADV-2"}, {AdvisoryID: "ADV-1"}},
					Exploits:         Exploits{{ExploitType: ExploitTypeGitHub, ID: "E1", URL: "u1"}},
					Metasploits:      []Metasploit{{Name: "m1"}},
				},
			},
		},
		{
			ServerName: "b",
			Family:     "ubuntu",
			Release:    "22.04",
			ScannedCves: VulnInfos{
				"CVE-1": {
					CveID: "CVE-1",
					AffectedPackages: PackageFixStatuses{
						{Name: "openssl", FixedIn: "3.0", FixState: "fixed"},
					},
					CveContents: CveContents{
						Nvd: []CveContent{{
							Cvss3Score:    7.5,
							Cvss3Severity: "high",
							SourceLink:    "https://nvd.example/CVE-1",
						}},
					},
					KEVs:             []KEV{{Type: ENISAKEVType}},
					DistroAdvisories: DistroAdvisories{{AdvisoryID: "ADV-1"}},
					Exploits: Exploits{
						{ExploitType: ExploitTypeGitHub, ID: "E1", URL: "u1"},
						{ExploitType: ExploitTypeExploitDB, ID: "E2", URL: "u2"},
					},
					Metasploits: []Metasploit{{Name: "m1"}},
				},
			},
		},
		{
			ServerName: "c",
			Family:     "debian",
			Release:    "12",
			ScannedCves: VulnInfos{
				"CVE-1": {
					CveID: "CVE-1",
					AffectedPackages: PackageFixStatuses{
						{Name: "curl", FixedIn: "1.3", FixState: "fixed"},
					},
					CveContents: CveContents{
						Nvd: []CveContent{{
							Cvss2Score:    5.0,
							Cvss2Severity: "medium",
						}},
					},
					Metasploits: []Metasploit{{Name: "m1"}, {Name: "m2"}},
				},
			},
		},
	}
}

func TestDedupByCveMergesHostsAndOccurrences(t *testing.T) {
	rs := dedupFixtureResults()
	got := DedupByCve(rs)

	if got.ScannedServers != 3 || got.SkippedServers != 0 || got.SkippedCves != 0 {
		t.Fatalf("counts: scanned=%d skippedServers=%d skippedCves=%d",
			got.ScannedServers, got.SkippedServers, got.SkippedCves)
	}
	if len(got.Cves) != 1 {
		t.Fatalf("len(Cves) = %d, want 1", len(got.Cves))
	}

	want := DedupedCve{
		CveID:            "CVE-1",
		Severity:         "CRITICAL",
		Cvss40Score:      9.1,
		Cvss3Score:       7.5,
		Cvss2Score:       5,
		HostCount:        3,
		AffectedServers:  []string{"a", "b", "c"},
		AffectedFamilies: []string{"debian", "ubuntu"},
		Occurrences: []Occurrence{
			{Server: "a", Family: "ubuntu", Release: "22.04", Package: "curl", FixedIn: "1.2", FixState: "fixed"},
			{Server: "b", Family: "ubuntu", Release: "22.04", Package: "openssl", FixedIn: "3.0", FixState: "fixed"},
			{Server: "c", Family: "debian", Release: "12", Package: "curl", FixedIn: "1.3", FixState: "fixed"},
		},
		SourceTypes:     []string{string(Nvd)},
		SourceLinks:     []string{"https://nvd.example/CVE-1"},
		KEVTypes:        []string{string(CISAKEVType), string(ENISAKEVType)},
		ExploitCount:    2,
		MetasploitCount: 2,
		AdvisoryIDs:     []string{"ADV-1", "ADV-2"},
		AllUnfixed:      false,
		VulnType:        "remote",
	}
	if !reflect.DeepEqual(got.Cves[0], want) {
		t.Fatalf("DedupedCve mismatch:\ngot:  %#v\nwant: %#v", got.Cves[0], want)
	}
}

func TestDedupByCveShuffleDeterministicAndPure(t *testing.T) {
	original := dedupFixtureResults()
	inputJSON, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	want := DedupByCve(original)

	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 10; i++ {
		shuffled := dedupFixtureResults()
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		got := DedupByCve(shuffled)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffle %d produced a different summary", i)
		}
	}

	afterJSON, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if string(inputJSON) != string(afterJSON) {
		t.Fatal("DedupByCve modified its input")
	}
	if original[0].ServerName != "a" || original[1].ServerName != "b" || original[2].ServerName != "c" {
		t.Fatalf("input order changed: %s %s %s", original[0].ServerName, original[1].ServerName, original[2].ServerName)
	}
}

func TestDedupByCveSortOrder(t *testing.T) {
	rs := ScanResults{
		dedupScoreServer("a1", "CVE-A", 9.0, 0, 0),
		dedupScoreServer("b1", "CVE-B", 9.0, 0, 0),
		dedupScoreServer("b2", "CVE-B", 0, 9.0, 0),
		dedupScoreServer("c1", "CVE-C", 9.0, 0, 0),
		dedupScoreServer("c2", "CVE-C", 0, 8.0, 0),
		dedupScoreServer("d1", "CVE-D", 8.0, 0, 0),
	}
	got := DedupByCve(rs)
	ids := make([]string, 0, len(got.Cves))
	for _, cve := range got.Cves {
		ids = append(ids, cve.CveID)
	}
	want := []string{"CVE-B", "CVE-C", "CVE-A", "CVE-D"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("CVE order = %v, want %v", ids, want)
	}
}

func dedupScoreServer(server, cve string, s40, s3, s2 float64) ScanResult {
	content := CveContent{Cvss40Score: s40, Cvss3Score: s3, Cvss2Score: s2}
	return ScanResult{
		ServerName: server,
		ScannedCves: VulnInfos{
			cve: {
				CveID: cve,
				CveContents: CveContents{
					Nvd: []CveContent{content},
				},
			},
		},
	}
}

func TestDedupByCveDegradedRecords(t *testing.T) {
	rs := ScanResults{
		{ServerName: ""},
		{ServerName: "nil-cves", ScannedCves: nil},
		{ServerName: "empty-cve-id", ScannedCves: VulnInfos{"": {}}},
		{ServerName: "no-content", ScannedCves: VulnInfos{"CVE-NONE": {CveID: "CVE-NONE"}}},
	}

	got := DedupByCve(rs)
	if got.ScannedServers != 3 {
		t.Errorf("ScannedServers = %d, want 3", got.ScannedServers)
	}
	if got.SkippedServers != 1 {
		t.Errorf("SkippedServers = %d, want 1", got.SkippedServers)
	}
	if got.SkippedCves != 1 {
		t.Errorf("SkippedCves = %d, want 1", got.SkippedCves)
	}
	if len(got.Cves) != 1 {
		t.Fatalf("len(Cves) = %d, want 1", len(got.Cves))
	}
	cve := got.Cves[0]
	if cve.CveID != "CVE-NONE" || cve.Severity != "NONE" {
		t.Fatalf("unexpected no-content CVE: %+v", cve)
	}
	if cve.Cvss40Score != 0 || cve.Cvss3Score != 0 || cve.Cvss2Score != 0 {
		t.Fatalf("scores not zero: %+v", cve)
	}
}

func TestDedupByCveScale(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale test in short mode")
	}

	const hosts = 200
	const cvesPerHost = 5000
	rs := make(ScanResults, 0, hosts)
	for h := 0; h < hosts; h++ {
		infos := make(VulnInfos, cvesPerHost)
		for i := 0; i < cvesPerHost; i++ {
			cveID := "CVE-" + string(rune('A'+i%26)) + "-" + itoa(i)
			infos[cveID] = VulnInfo{
				CveID: cveID,
				AffectedPackages: PackageFixStatuses{{
					Name: "pkg-" + itoa(i%500),
				}},
			}
		}
		rs = append(rs, ScanResult{ServerName: "host-" + itoa(h), ScannedCves: infos})
	}

	start := time.Now()
	summary := DedupByCve(rs)
	elapsed := time.Since(start)
	t.Logf("DedupByCve scale elapsed: %v", elapsed)
	if raceInstrumentedTest() {
		t.Log("skipping 3s performance threshold under race instrumentation")
	} else if elapsed > 3*time.Second {
		t.Fatalf("DedupByCve took %v, want < 3s", elapsed)
	}
	if summary.ScannedServers != hosts {
		t.Fatalf("ScannedServers = %d, want %d", summary.ScannedServers, hosts)
	}
	if len(summary.Cves) != cvesPerHost {
		t.Fatalf("len(Cves) = %d, want %d", len(summary.Cves), cvesPerHost)
	}
}

func raceInstrumentedTest() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, setting := range info.Settings {
		if setting.Key == "-race" {
			return setting.Value == "true"
		}
	}
	return false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
