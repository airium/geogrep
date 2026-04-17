package geogrep

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

func printStartup(discovery DiscoveryResult, queryCount int) {
	mode := "current directory"
	if discovery.FromExeDir {
		mode = "executable directory fallback"
	}
	fmt.Printf("[geogrep] db_root=%s (%s) databases=%d queries=%d\n", discovery.RootDir, mode, len(discovery.Databases), queryCount)
}

func printDiagnostics(diags []Diagnostic) {
	for _, diag := range diags {
		fmt.Printf("[%s] %s: %s\n", strings.ToUpper(diag.Level), diag.Scope, diag.Message)
	}
}

func printQueryResults(results []QueryResult, reportEmpty bool) {
	for i, result := range results {
		fmt.Printf("\n[%d] input=%s kind=%s\n", i+1, result.Query.Raw, result.Query.Kind)
		if len(result.DatabaseResult) == 0 {
			fmt.Println("  no matches")
			continue
		}
		for _, db := range result.DatabaseResult {
			if db.Matched {
				fmt.Printf("  %s: %d match(es)\n", db.Database, len(db.Matches))
				for _, match := range db.Matches {
					sourceCol, formatCol, categoryCol := formatMatchColumns(db.Database, match)
					if categoryCol != "" {
						fmt.Printf("    - %s | %s | %s | %s\n", sourceCol, formatCol, categoryCol, match.Rule)
					} else {
						fmt.Printf("    - %s | %s | %s\n", sourceCol, formatCol, match.Rule)
					}
				}
				continue
			}
			if reportEmpty {
				fmt.Printf("  %s: no match\n", db.Database)
			}
		}
	}
}

func formatMatchColumns(dbName string, match MatchRecord) (string, string, string) {
	sourceCol := strings.TrimSpace(match.Source)
	formatCol := strings.TrimSpace(match.Format)
	categoryCol := strings.TrimSpace(match.SubEntry)

	if sourceCol == "" {
		sourceCol = dbName
	}

	if idx := strings.IndexByte(sourceCol, '/'); idx > 0 {
		dbCol := sourceCol[:idx]
		fileCol := sourceCol[idx+1:]
		sourceCol = dbCol
		categoryCol = fileCol
	}

	if sourceCol == "" {
		sourceCol = dbName
	}

	return sourceCol, formatCol, categoryCol
}

func writeJSON(path string, discovery DiscoveryResult, queries []Query, results []QueryResult, diags []Diagnostic, reportEmpty bool) error {
	doc := buildExportDocument(discovery, queries, results, diags, reportEmpty)

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func buildExportDocument(discovery DiscoveryResult, queries []Query, results []QueryResult, diags []Diagnostic, reportEmpty bool) ExportDocument {
	return ExportDocument{
		Metadata: ExportMetadata{
			GeneratedAt:    time.Now().UTC(),
			DatabaseCount:  len(discovery.Databases),
			QueryCount:     len(queries),
			ReportEmpty:    reportEmpty,
			UsedExecutable: discovery.FromExeDir,
		},
		Results:     results,
		Diagnostics: diags,
	}
}
