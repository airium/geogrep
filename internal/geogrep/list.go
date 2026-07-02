package geogrep

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type listedRule struct {
	Database string `json:"database"`
	Source   string `json:"source"`
	Format   string `json:"format"`
	Ruleset  string `json:"ruleset"`
	Rule     string `json:"rule"`
}

type listedRuleset struct {
	Ruleset string       `json:"ruleset"`
	Rules   []listedRule `json:"rules,omitempty"`
}

type ListMetadata struct {
	GeneratedAt    time.Time `json:"generated_at"`
	DatabaseCount  int       `json:"database_count"`
	RulesetCount   int       `json:"ruleset_count"`
	UsedExecutable bool      `json:"used_executable_dir_fallback"`
}

type ListDocument struct {
	Metadata    ListMetadata    `json:"metadata"`
	Results     []listedRuleset `json:"results"`
	Diagnostics []Diagnostic    `json:"diagnostics,omitempty"`
}

type listOptions struct {
	IncludeMMDB bool
}

func runList(cfg CLIConfig) int {
	discovery, err := resolveDiscovery(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery error: %v\n", err)
		return 1
	}

	printListStartup(discovery, len(cfg.Rulesets))

	databases, diagnostics := loadDatabases(discovery)
	defer closeDatabases(databases)

	if len(diagnostics) > 0 {
		printDiagnostics(diagnostics)
	}

	opts := resolveListOptions(databases, listOptions{IncludeMMDB: cfg.IncludeMMDB})
	printListMMDBNotice(databases, cfg.IncludeMMDB, opts.IncludeMMDB)

	results := listRulesetsWithOptions(databases, cfg.Rulesets, opts)
	printListResults(results)

	if cfg.JSONPath != "" {
		if err := writeListJSON(cfg.JSONPath, discovery, results, diagnostics); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write JSON output: %v\n", err)
			return 1
		}
		fmt.Printf("\n[geogrep] wrote JSON list to %s\n", cfg.JSONPath)
	}

	return 0
}

func listRulesets(databases []LoadedDatabase, rulesets []string) []listedRuleset {
	return listRulesetsWithOptions(databases, rulesets, listOptions{})
}

func listRulesetsWithOptions(databases []LoadedDatabase, rulesets []string, opts listOptions) []listedRuleset {
	opts = resolveListOptions(databases, opts)

	results := make([]listedRuleset, 0, len(rulesets))
	for _, ruleset := range rulesets {
		ruleset = strings.TrimSpace(ruleset)
		result := listedRuleset{Ruleset: ruleset}
		for _, db := range databases {
			for _, source := range db.Sources {
				result.Rules = append(result.Rules, listSourceRules(db.Name, source, ruleset, opts)...)
			}
		}
		results = append(results, result)
	}
	return results
}

func listSourceRules(dbName string, source LoadedSource, requestedRuleset string, opts listOptions) []listedRule {
	rules := make([]listedRule, 0)
	for _, rule := range source.GeoIPRules {
		if matchedRuleset, ok := matchRuleRuleset(rule.SubEntry, dbName, source, requestedRuleset); ok {
			rules = append(rules, newListedRule(dbName, source, matchedRuleset, rule.Rule))
		}
	}
	for _, rule := range source.DomainRule {
		if matchedRuleset, ok := matchRuleRuleset(rule.SubEntry, dbName, source, requestedRuleset); ok {
			rules = append(rules, newListedRule(dbName, source, matchedRuleset, rule.Rule))
		}
	}
	if opts.IncludeMMDB && source.MMDB != nil {
		rules = append(rules, listMMDBRulesCached(dbName, source, requestedRuleset)...)
	}
	return rules
}

func resolveListOptions(databases []LoadedDatabase, opts listOptions) listOptions {
	if opts.IncludeMMDB {
		return opts
	}
	if onlyMMDBDatabaseType(databases) {
		opts.IncludeMMDB = true
	}
	return opts
}

func onlyMMDBDatabaseType(databases []LoadedDatabase) bool {
	sourceCount := 0
	for _, db := range databases {
		for _, source := range db.Sources {
			sourceType := listSourceDatabaseType(source)
			if sourceType == "" {
				return false
			}
			sourceCount++
			if sourceType != "mmdb" {
				return false
			}
		}
	}
	return sourceCount > 0
}

func hasMMDBDatabaseType(databases []LoadedDatabase) bool {
	for _, db := range databases {
		for _, source := range db.Sources {
			if listSourceDatabaseType(source) == "mmdb" {
				return true
			}
		}
	}
	return false
}

func listSourceDatabaseType(source LoadedSource) string {
	if source.MMDB != nil {
		return "mmdb"
	}
	return strings.ToLower(strings.TrimSpace(source.Format))
}

func matchRuleRuleset(subEntry, dbName string, source LoadedSource, requestedRuleset string) (string, bool) {
	subEntry = strings.TrimSpace(subEntry)
	if subEntry != "" {
		if sameRulesetName(subEntry, requestedRuleset) {
			return subEntry, true
		}
		if !isTechnicalRulesetName(subEntry) {
			return "", false
		}
	}
	for _, candidate := range sourceRulesetCandidates(source) {
		if sameRulesetName(candidate, requestedRuleset) {
			return candidate, true
		}
	}
	return "", false
}

func sameRulesetName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func isTechnicalRulesetName(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "rule[") || strings.HasPrefix(value, "behavior:")
}

func sourceRulesetCandidates(source LoadedSource) []string {
	display := strings.TrimSpace(path.Clean(filepath.ToSlash(source.Display)))
	if display == "." || display == "" {
		display = ""
	}

	base := path.Base(display)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	candidates := make([]string, 0, 3)
	for _, candidate := range []string{display, base, stem} {
		if candidate == "" || candidate == "." {
			continue
		}
		seen := false
		for _, existing := range candidates {
			if existing == candidate {
				seen = true
				break
			}
		}
		if !seen {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func newListedRule(dbName string, source LoadedSource, ruleset, rule string) listedRule {
	return listedRule{
		Database: dbName,
		Source:   filepath.ToSlash(source.Display),
		Format:   source.Format,
		Ruleset:  ruleset,
		Rule:     rule,
	}
}

func printListStartup(discovery DiscoveryResult, rulesetCount int) {
	mode := "current directory"
	if discovery.FromExeDir {
		mode = "executable directory fallback"
	}
	fmt.Printf("[geogrep] db_root=%s (%s) databases=%d rulesets=%d\n", discovery.RootDir, mode, len(discovery.Databases), rulesetCount)
}

func printListMMDBNotice(databases []LoadedDatabase, requestedIncludeMMDB, effectiveIncludeMMDB bool) {
	if requestedIncludeMMDB || !hasMMDBDatabaseType(databases) {
		return
	}
	if effectiveIncludeMMDB {
		fmt.Println("[geogrep] only MMDB/MetaDB databases found; including MMDB/MetaDB data automatically")
		return
	}
	fmt.Println("[geogrep] MMDB/MetaDB databases skipped; add --include-mmdb to include them")
}

func printListResults(results []listedRuleset) {
	for i, result := range results {
		fmt.Printf("\n[%d] ruleset=%s\n", i+1, result.Ruleset)
		if len(result.Rules) == 0 {
			fmt.Println("  no rules")
			continue
		}

		currentDB := ""
		for _, rule := range result.Rules {
			if rule.Database != currentDB {
				currentDB = rule.Database
				fmt.Printf("  %s:\n", currentDB)
			}
			if rule.Ruleset != "" {
				fmt.Printf("    - %s | %s | %s | %s\n", rule.Source, rule.Format, rule.Ruleset, rule.Rule)
			} else {
				fmt.Printf("    - %s | %s | %s\n", rule.Source, rule.Format, rule.Rule)
			}
		}
	}
}

func writeListJSON(path string, discovery DiscoveryResult, results []listedRuleset, diags []Diagnostic) error {
	doc := buildListDocument(discovery, results, diags)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func buildListDocument(discovery DiscoveryResult, results []listedRuleset, diags []Diagnostic) ListDocument {
	return ListDocument{
		Metadata: ListMetadata{
			GeneratedAt:    time.Now().UTC(),
			DatabaseCount:  len(discovery.Databases),
			RulesetCount:   len(results),
			UsedExecutable: discovery.FromExeDir,
		},
		Results:     results,
		Diagnostics: diags,
	}
}
