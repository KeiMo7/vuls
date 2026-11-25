package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
)

func TestScanPseudoQueueBridge(t *testing.T) {
	zeroDir, zeroReport := runPseudoScanForTest(t, 0)
	twoDir, twoReport := runPseudoScanForTest(t, 2)

	zeroFiles := listHostJSONFiles(t, zeroDir)
	twoFiles := listHostJSONFiles(t, twoDir)
	if len(zeroFiles) != 3 || len(twoFiles) != 3 {
		t.Fatalf("file counts: workers0=%v workers2=%v", zeroFiles, twoFiles)
	}
	if !reflect.DeepEqual(zeroFiles, twoFiles) {
		t.Fatalf("file sets differ:\nworkers0=%v\nworkers2=%v", zeroFiles, twoFiles)
	}

	for _, name := range zeroFiles {
		zero := readNormalizedHostJSON(t, filepath.Join(zeroDir, name))
		two := readNormalizedHostJSON(t, filepath.Join(twoDir, name))
		if !reflect.DeepEqual(zero, two) {
			t.Fatalf("normalized JSON for %s differs\nzero=%#v\ntwo=%#v", name, zero, two)
		}
	}

	if twoReport.Succeeded != 3 {
		t.Fatalf("Workers=2 Succeeded = %d, want 3; report=%+v", twoReport.Succeeded, twoReport)
	}
	if twoReport.MaxInFlight > 2 {
		t.Fatalf("MaxInFlight = %d, must be <= 2", twoReport.MaxInFlight)
	}
	if zeroReport.Succeeded != 0 {
		t.Fatalf("default path must not populate queue report, got %+v", zeroReport)
	}
}

func runPseudoScanForTest(t *testing.T, workers int) (string, queueReportForTest) {
	t.Helper()
	servers = nil
	errServers = nil

	targets := make(map[string]config.ServerInfo, 3)
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("pseudo-%d", i)
		targets[name] = config.ServerInfo{
			ServerName: name,
			Type:       constant.ServerTypePseudo,
		}
	}

	root := t.TempDir()
	s := &Scanner{
		ResultsDir:     root,
		TimeoutSec:     30,
		ScanTimeoutSec: 30,
		Targets:        targets,
		Workers:        workers,
		MaxAttempts:    1,
	}
	if err := s.Scan(); err != nil {
		t.Fatalf("Scan(workers=%d): %v", workers, err)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		t.Fatalf("result directories = %v, want one directory", entries)
	}
	return filepath.Join(root, entries[0].Name()), queueReportForTest{
		Succeeded:   s.LastReport.Succeeded,
		MaxInFlight: s.LastReport.MaxInFlight,
	}
}

type queueReportForTest struct {
	Succeeded   int
	MaxInFlight int
}

func listHostJSONFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	return files
}

func readNormalizedHostJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"jsonVersion",
		"scannedAt",
		"scannedVersion",
		"scannedRevision",
		"reportedAt",
		"reportedVersion",
		"reportedRevision",
	} {
		delete(result, key)
	}
	return result
}
