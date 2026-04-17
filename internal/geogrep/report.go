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
					if match.SubEntry != "" {
						fmt.Printf("    - %s | %s | %s | %s\n", match.Source, match.Format, match.SubEntry, match.Rule)
					} else {
						fmt.Printf("    - %s | %s | %s\n", match.Source, match.Format, match.Rule)
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
			DatabaseRoot:   discovery.RootDir,
			DatabaseCount:  len(discovery.Databases),
			QueryCount:     len(queries),
			ReportEmpty:    reportEmpty,
			UsedExecutable: discovery.FromExeDir,
		},
		Results:     results,
		Diagnostics: diags,
	}
}
