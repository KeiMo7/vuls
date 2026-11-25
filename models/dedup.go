package models

import (
	"cmp"
	"slices"
	"strings"
)

// DedupSummary is the cross-host deduplication result.
type DedupSummary struct {
	// ScannedServers is the number of scan results with a usable host identity.
	ScannedServers int `json:"scannedServers"`
	// SkippedServers is the number of results without a usable host identity.
	SkippedServers int `json:"skippedServers"`
	// SkippedCves is the number of vulnerability entries without a CVE ID.
	SkippedCves int `json:"skippedCves"`
	// Cves are deduplicated CVE records sorted by score, host count, and ID.
	Cves []DedupedCve `json:"cves"`
}

// DedupedCve is one CVE merged across all scanned hosts.
type DedupedCve struct {
	// CveID is the unique CVE identifier.
	CveID string `json:"cveID"`
	// Severity is the uppercase severity selected by CVSS version priority.
	Severity string `json:"severity"`
	// Cvss40Score is the maximum CVSS v4.0 score across hosts.
	Cvss40Score float64 `json:"cvss40Score"`
	// Cvss3Score is the maximum CVSS v3 score across hosts.
	Cvss3Score float64 `json:"cvss3Score"`
	// Cvss2Score is the maximum CVSS v2 score across hosts.
	Cvss2Score float64 `json:"cvss2Score"`
	// HostCount is the number of distinct affected hosts.
	HostCount int `json:"hostCount"`
	// AffectedServers is the sorted set of affected host identities.
	AffectedServers []string `json:"affectedServers"`
	// AffectedFamilies is the sorted set of affected OS families.
	AffectedFamilies []string `json:"affectedFamilies"`
	// Occurrences are package-level occurrences sorted by server, package, and fix.
	Occurrences []Occurrence `json:"occurrences"`
	// SourceTypes is the sorted set of CVE content source types.
	SourceTypes []string `json:"sourceTypes"`
	// SourceLinks is the sorted set of CVE source links.
	SourceLinks []string `json:"sourceLinks"`
	// KEVTypes is the sorted set of KEV source types.
	KEVTypes []string `json:"kevTypes"`
	// ExploitCount is the number of distinct exploit records.
	ExploitCount int `json:"exploitCount"`
	// MetasploitCount is the number of distinct Metasploit records.
	MetasploitCount int `json:"metasploitCount"`
	// AdvisoryIDs is the sorted set of distribution advisory IDs.
	AdvisoryIDs []string `json:"advisoryIDs"`
	// AllUnfixed reports whether every retained occurrence is marked not fixed yet.
	AllUnfixed bool `json:"allUnfixed"`
	// VulnType is the vulnerability type carried by the merged CVE records.
	VulnType string `json:"vulnType"`
}

// Occurrence is one package occurrence of a CVE on one host.
type Occurrence struct {
	// Server is the host identity.
	Server string `json:"server"`
	// Family is the host OS family.
	Family string `json:"family"`
	// Release is the host OS release.
	Release string `json:"release"`
	// Package is the affected package name.
	Package string `json:"package"`
	// FixedIn is the version containing the fix.
	FixedIn string `json:"fixedIn"`
	// NotFixedYet reports whether no fix is available for the package.
	NotFixedYet bool `json:"notFixedYet"`
	// FixState is the detector-provided fix state.
	FixState string `json:"fixState"`
}

type occurrenceKey struct {
	serverID int
	pkg      string
}

type dedupHost struct {
	name     string
	families map[string]struct{}
}

type cveAccumulator struct {
	cve DedupedCve

	servers    map[int]struct{}
	sourceType map[string]struct{}
	sourceLink map[string]struct{}
	kevType    map[string]struct{}
	advisory   map[string]struct{}
	exploits   map[string]struct{}
	metasploit map[string]struct{}
	vulnTypes  map[string]struct{}

	occurrenceIndex map[occurrenceKey]int

	severity40 string
	severity3  string
	severity2  string
}

// DedupByCve merges same-CVE records across multiple scan results.
func DedupByCve(rs ScanResults) DedupSummary {
	summary := DedupSummary{Cves: []DedupedCve{}}
	accumulators := make(map[string]*cveAccumulator)
	hostIDs := make(map[string]int)
	hosts := []dedupHost{}

	hostIDFor := func(server, family string) int {
		if id, ok := hostIDs[server]; ok {
			if family != "" {
				addToSet(&hosts[id].families, family)
			}
			return id
		}
		id := len(hosts)
		hostIDs[server] = id
		host := dedupHost{name: server}
		if family != "" {
			host.families = map[string]struct{}{family: {}}
		}
		hosts = append(hosts, host)
		return id
	}

	for _, result := range rs {
		server := result.ReportFileName()
		if server == "" {
			server = result.ServerName
		}
		if server == "" {
			summary.SkippedServers++
			continue
		}
		summary.ScannedServers++
		hostID := hostIDFor(server, result.Family)

		for mapCveID, vuln := range result.ScannedCves {
			cveID := vuln.CveID
			if cveID == "" {
				cveID = mapCveID
			}
			if cveID == "" {
				summary.SkippedCves++
				continue
			}

			acc := accumulators[cveID]
			if acc == nil {
				acc = newCveAccumulator(cveID)
				accumulators[cveID] = acc
			}
			acc.addVuln(hostID, server, result, vuln)
		}
	}

	cves := make([]DedupedCve, 0, len(accumulators))
	for _, acc := range accumulators {
		cves = append(cves, acc.finish(hosts))
	}

	slices.SortFunc(cves, compareDedupedCve)
	summary.Cves = cves
	return summary
}

func newCveAccumulator(cveID string) *cveAccumulator {
	return &cveAccumulator{
		cve: DedupedCve{
			CveID:           cveID,
			Occurrences:     []Occurrence{},
			AffectedServers: []string{},
		},
		servers:         make(map[int]struct{}),
		occurrenceIndex: make(map[occurrenceKey]int),
	}
}

func addToSet(set *map[string]struct{}, value string) {
	if *set == nil {
		*set = make(map[string]struct{})
	}
	(*set)[value] = struct{}{}
}

func (a *cveAccumulator) addVuln(hostID int, server string, result ScanResult, vuln VulnInfo) {
	a.servers[hostID] = struct{}{}
	if vuln.VulnType != "" {
		addToSet(&a.vulnTypes, vuln.VulnType)
	}

	a.addScores(vuln)
	a.addOccurrences(hostID, server, result, vuln)
	a.addEnrichment(vuln)
}

func (a *cveAccumulator) addScores(vuln VulnInfo) {
	// Empty CveContents has no CVSS values and the accessors only allocate and
	// scan source-order tables, so take the same zero-score result directly.
	if len(vuln.CveContents) == 0 {
		return
	}

	cvss40 := vuln.MaxCvss40Score()
	if score := cvss40.Value.Score; score > a.cve.Cvss40Score {
		a.cve.Cvss40Score = score
		a.severity40 = cvss40.Value.Severity
	} else if score == a.cve.Cvss40Score && score > 0 {
		a.severity40 = preferredSeverity(a.severity40, cvss40.Value.Severity)
	}

	cvss3 := vuln.MaxCvss3Score()
	if score := cvss3.Value.Score; score > a.cve.Cvss3Score {
		a.cve.Cvss3Score = score
		a.severity3 = cvss3.Value.Severity
	} else if score == a.cve.Cvss3Score && score > 0 {
		a.severity3 = preferredSeverity(a.severity3, cvss3.Value.Severity)
	}

	cvss2 := vuln.MaxCvss2Score()
	if score := cvss2.Value.Score; score > a.cve.Cvss2Score {
		a.cve.Cvss2Score = score
		a.severity2 = cvss2.Value.Severity
	} else if score == a.cve.Cvss2Score && score > 0 {
		a.severity2 = preferredSeverity(a.severity2, cvss2.Value.Severity)
	}
}

func preferredSeverity(current, candidate string) string {
	if current == "" {
		return candidate
	}
	if candidate != "" && strings.ToUpper(candidate) < strings.ToUpper(current) {
		return candidate
	}
	return current
}

func (a *cveAccumulator) addOccurrences(hostID int, server string, result ScanResult, vuln VulnInfo) {
	for _, pkg := range vuln.AffectedPackages {
		occurrence := Occurrence{
			Server:      server,
			Family:      result.Family,
			Release:     result.Release,
			Package:     pkg.Name,
			FixedIn:     pkg.FixedIn,
			NotFixedYet: pkg.NotFixedYet,
			FixState:    pkg.FixState,
		}
		key := occurrenceKey{serverID: hostID, pkg: pkg.Name}
		if idx, ok := a.occurrenceIndex[key]; ok {
			if betterOccurrence(occurrence, a.cve.Occurrences[idx]) {
				a.cve.Occurrences[idx] = occurrence
			}
			continue
		}

		a.occurrenceIndex[key] = len(a.cve.Occurrences)
		a.cve.Occurrences = append(a.cve.Occurrences, occurrence)
	}
}

func betterOccurrence(candidate, current Occurrence) bool {
	candidateEmptyFixed := candidate.FixedIn == ""
	currentEmptyFixed := current.FixedIn == ""
	if candidateEmptyFixed != currentEmptyFixed {
		return !candidateEmptyFixed
	}
	if candidate.FixedIn != current.FixedIn {
		return candidate.FixedIn < current.FixedIn
	}
	return candidate.FixState < current.FixState
}

func (a *cveAccumulator) addEnrichment(vuln VulnInfo) {
	for sourceType, contents := range vuln.CveContents {
		addToSet(&a.sourceType, string(sourceType))
		for _, content := range contents {
			if content.SourceLink != "" {
				addToSet(&a.sourceLink, content.SourceLink)
			}
		}
	}

	for _, kev := range vuln.KEVs {
		if kev.Type != "" {
			addToSet(&a.kevType, string(kev.Type))
		}
	}

	for _, advisory := range vuln.DistroAdvisories {
		if advisory.AdvisoryID != "" {
			addToSet(&a.advisory, advisory.AdvisoryID)
		}
	}

	for _, exploit := range vuln.Exploits {
		if a.exploits == nil {
			a.exploits = make(map[string]struct{})
		}
		key := strings.Join([]string{string(exploit.ExploitType), exploit.ID, exploit.URL}, "\x00")
		a.exploits[key] = struct{}{}
	}

	for _, metasploit := range vuln.Metasploits {
		if a.metasploit == nil {
			a.metasploit = make(map[string]struct{})
		}
		// Name is the module identifier. Fall back to title/URL only for records
		// that do not carry it.
		key := metasploit.Name
		if key == "" {
			key = metasploit.Title
		}
		if key == "" && len(metasploit.URLs) > 0 {
			key = metasploit.URLs[0]
		}
		a.metasploit[key] = struct{}{}
	}
}

func (a *cveAccumulator) finish(hosts []dedupHost) DedupedCve {
	d := a.cve
	serverNames := make([]string, 0, len(a.servers))
	familySet := make(map[string]struct{})
	for hostID := range a.servers {
		if hostID < 0 || hostID >= len(hosts) {
			continue
		}
		host := hosts[hostID]
		serverNames = append(serverNames, host.name)
		for family := range host.families {
			familySet[family] = struct{}{}
		}
	}
	slices.Sort(serverNames)
	d.AffectedServers = serverNames
	d.AffectedFamilies = sortedSet(familySet)
	d.SourceTypes = sortedSet(a.sourceType)
	d.SourceLinks = sortedSet(a.sourceLink)
	d.KEVTypes = sortedSet(a.kevType)
	d.AdvisoryIDs = sortedSet(a.advisory)
	d.ExploitCount = len(a.exploits)
	d.MetasploitCount = len(a.metasploit)
	d.HostCount = len(a.servers)
	d.VulnType = firstSortedValue(a.vulnTypes)
	if d.Occurrences == nil {
		d.Occurrences = []Occurrence{}
	}

	slices.SortFunc(d.Occurrences, func(x, y Occurrence) int {
		return cmp.Or(
			cmp.Compare(x.Server, y.Server),
			cmp.Compare(x.Package, y.Package),
			cmp.Compare(x.FixedIn, y.FixedIn),
		)
	})

	d.AllUnfixed = true
	for _, occurrence := range d.Occurrences {
		if !occurrence.NotFixedYet {
			d.AllUnfixed = false
			break
		}
	}

	switch {
	case d.Cvss40Score != 0:
		d.Severity = strings.ToUpper(a.severity40)
	case d.Cvss3Score != 0:
		d.Severity = strings.ToUpper(a.severity3)
	case d.Cvss2Score != 0:
		d.Severity = strings.ToUpper(a.severity2)
	default:
		d.Severity = "NONE"
	}
	if d.Severity == "" {
		d.Severity = "UNKNOWN"
	}

	return d
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func firstSortedValue(set map[string]struct{}) string {
	if len(set) == 0 {
		return ""
	}
	values := sortedSet(set)
	return values[0]
}

func primaryCvssScore(cve DedupedCve) float64 {
	switch {
	case cve.Cvss40Score != 0:
		return cve.Cvss40Score
	case cve.Cvss3Score != 0:
		return cve.Cvss3Score
	default:
		return cve.Cvss2Score
	}
}

func compareDedupedCve(a, b DedupedCve) int {
	return cmp.Or(
		-cmp.Compare(primaryCvssScore(a), primaryCvssScore(b)),
		-cmp.Compare(a.HostCount, b.HostCount),
		cmp.Compare(a.CveID, b.CveID),
	)
}
