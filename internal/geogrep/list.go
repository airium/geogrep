package geogrep

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
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

	results := listRulesets(databases, cfg.Rulesets)
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
	results := make([]listedRuleset, 0, len(rulesets))
	for _, ruleset := range rulesets {
		ruleset = strings.TrimSpace(ruleset)
		result := listedRuleset{Ruleset: ruleset}
		for _, db := range databases {
			for _, source := range db.Sources {
				result.Rules = append(result.Rules, listSourceRules(db.Name, source, ruleset)...)
			}
		}
		results = append(results, result)
	}
	return results
}

func listSourceRules(dbName string, source LoadedSource, requestedRuleset string) []listedRule {
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
	if source.MMDB != nil {
		rules = append(rules, listMMDBRules(dbName, source, requestedRuleset)...)
	}
	return rules
}

func listMMDBRules(dbName string, source LoadedSource, requestedRuleset string) []listedRule {
	rules := make([]GeoIPRule, 0)
	for result := range source.MMDB.Reader.Networks() {
		if err := result.Err(); err != nil {
			continue
		}
		var payload any
		if err := result.Decode(&payload); err != nil || payload == nil {
			continue
		}
		rules = append(rules, GeoIPRule{
			SubEntry: deriveMMDBSubEntry(payload),
			Rule:     result.Prefix().Masked().String(),
			Prefix:   result.Prefix().Masked(),
		})
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].SubEntry != rules[j].SubEntry {
			return rules[i].SubEntry < rules[j].SubEntry
		}
		return rules[i].Prefix.String() < rules[j].Prefix.String()
	})

	listed := make([]listedRule, 0, len(rules))
	for _, rule := range rules {
		if matchedRuleset, ok := matchRuleRuleset(rule.SubEntry, dbName, source, requestedRuleset); ok {
			listed = append(listed, newListedRule(dbName, source, matchedRuleset, rule.Rule))
		}
	}
	return listed
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
