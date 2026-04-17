package geogrep

import (
	"fmt"
	"os"
)

// Execute runs the geogrep CLI flow and returns a process exit code.
func Execute(args []string) int {
	cfg, err := parseCLIArgs(args)
	if err != nil {
		printUsage(err)
		return 2
	}

	if cfg.Command == "version" {
		printVersion()
		return 0
	}

	queries, err := normalizeQueries(cfg.Inputs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "input error: %v\n", err)
		return 2
	}

	discovery, err := resolveDiscovery(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery error: %v\n", err)
		return 1
	}

	printStartup(discovery, len(queries))

	databases, diagnostics := loadDatabases(discovery)
	defer closeDatabases(databases)

	if len(diagnostics) > 0 {
		printDiagnostics(diagnostics)
	}

	results := runLookups(queries, databases, cfg.ReportEmpty)
	printQueryResults(results, cfg.ReportEmpty)

	if cfg.JSONPath != "" {
		if err := writeJSON(cfg.JSONPath, discovery, queries, results, diagnostics, cfg.ReportEmpty); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write JSON output: %v\n", err)
			return 1
		}
		fmt.Printf("\n[geogrep] wrote JSON report to %s\n", cfg.JSONPath)
	}

	return 0
}

func printUsage(parseErr error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", parseErr)
	fmt.Fprintln(os.Stderr, "usage:\n  geogrep find [--json RESULT_PATH] [-v|--verbose[=N]] [-db DB_DIR|DB_FILE] [-4 IPv4/CIDR] [-6 IPv6/CIDR6] [-d DOMAIN] [-k KEYWORD] IPv4/CIDR/IPv6/CIDR6/DOMAIN/KEYWORD\n  geogrep version")
}
