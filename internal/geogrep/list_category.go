package geogrep

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type listedCategory struct {
	Database string `json:"database"`
	Source   string `json:"source"`
	Format   string `json:"format"`
	Category string `json:"category"`
}

type listedCategoryPattern struct {
	Pattern    string           `json:"pattern"`
	Categories []listedCategory `json:"categories,omitempty"`
}

type ListCategoryMetadata struct {
	GeneratedAt    time.Time `json:"generated_at"`
	DatabaseCount  int       `json:"database_count"`
	PatternCount   int       `json:"pattern_count"`
	UsedExecutable bool      `json:"used_executable_dir_fallback"`
}

type ListCategoryDocument struct {
	Metadata    ListCategoryMetadata    `json:"metadata"`
	Results     []listedCategoryPattern `json:"results"`
	Diagnostics []Diagnostic            `json:"diagnostics,omitempty"`
}

type CategoryListMetadata struct {
	GeneratedAt    time.Time `json:"generated_at"`
	DatabaseCount  int       `json:"database_count"`
	CategoryCount  int       `json:"category_count"`
	UsedExecutable bool      `json:"used_executable_dir_fallback"`
}

type CategoryListDocument struct {
	Metadata    CategoryListMetadata `json:"metadata"`
	Categories  []listedCategory     `json:"categories"`
	Diagnostics []Diagnostic         `json:"diagnostics,omitempty"`
}

type compiledCategoryPattern struct {
	Pattern string
	Regex   bool
	Expr    *regexp.Regexp
	Needle  string
}

func runListAllCategories(cfg CLIConfig) int {
	discovery, err := resolveDiscovery(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery error: %v\n", err)
		return 1
	}

	printListAllCategoriesStartup(discovery)

	databases, diagnostics := loadDatabases(discovery)
	defer closeDatabases(databases)

	if len(diagnostics) > 0 {
		printDiagnostics(diagnostics)
	}

	opts := resolveListOptions(databases, listOptions{IncludeMMDB: cfg.IncludeMMDB})
	printListMMDBNotice(databases, cfg.IncludeMMDB, opts.IncludeMMDB)

	categories := listAllCategoriesWithOptions(databases, opts)
	printListAllCategoriesResults(categories)

	if cfg.JSONPath != "" {
		if err := writeCategoryListJSON(cfg.JSONPath, discovery, categories, diagnostics); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write JSON category list: %v\n", err)
			return 1
		}
		fmt.Printf("\n[geogrep] wrote JSON category list to %s\n", cfg.JSONPath)
	}

	return 0
}

func runListCategory(cfg CLIConfig) int {
	patterns, err := compileCategoryPatterns(cfg.CategoryPatterns, cfg.CategoryRegex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "category search error: %v\n", err)
		return 2
	}

	discovery, err := resolveDiscovery(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery error: %v\n", err)
		return 1
	}

	printListCategoryStartup(discovery, len(patterns))

	databases, diagnostics := loadDatabases(discovery)
	defer closeDatabases(databases)

	if len(diagnostics) > 0 {
		printDiagnostics(diagnostics)
	}

	opts := resolveListOptions(databases, listOptions{IncludeMMDB: cfg.IncludeMMDB, Regex: cfg.CategoryRegex})
	printListMMDBNotice(databases, cfg.IncludeMMDB, opts.IncludeMMDB)

	results := listCategoriesWithCompiledPatterns(databases, patterns, opts)
	printListCategoryResults(results)

	if cfg.JSONPath != "" {
		if err := writeListCategoryJSON(cfg.JSONPath, discovery, results, diagnostics); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write JSON category list: %v\n", err)
			return 1
		}
		fmt.Printf("\n[geogrep] wrote JSON category list to %s\n", cfg.JSONPath)
	}

	return 0
}

func listAllCategories(databases []LoadedDatabase) []listedCategory {
	return listAllCategoriesWithOptions(databases, listOptions{})
}

func listAllCategoriesWithOptions(databases []LoadedDatabase, opts listOptions) []listedCategory {
	opts = resolveListOptions(databases, opts)
	return collectListedCategories(databases, opts)
}

func listCategories(databases []LoadedDatabase, patterns []string) ([]listedCategoryPattern, error) {
	return listCategoriesWithOptions(databases, patterns, listOptions{})
}

func listCategoriesWithOptions(databases []LoadedDatabase, patterns []string, opts listOptions) ([]listedCategoryPattern, error) {
	compiled, err := compileCategoryPatterns(patterns, opts.Regex)
	if err != nil {
		return nil, err
	}
	return listCategoriesWithCompiledPatterns(databases, compiled, opts), nil
}

func compileCategoryPatterns(patterns []string, regex bool) ([]compiledCategoryPattern, error) {
	compiled := make([]compiledCategoryPattern, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("empty category search value")
		}
		item := compiledCategoryPattern{Pattern: pattern, Regex: regex}
		if regex {
			expr, err := regexp.Compile("(?i)(?:" + pattern + ")")
			if err != nil {
				return nil, fmt.Errorf("%q: %w", pattern, err)
			}
			item.Expr = expr
		} else {
			item.Needle = strings.ToLower(pattern)
		}
		compiled = append(compiled, item)
	}
	return compiled, nil
}

func listCategoriesWithCompiledPatterns(databases []LoadedDatabase, patterns []compiledCategoryPattern, opts listOptions) []listedCategoryPattern {
	opts = resolveListOptions(databases, opts)

	categories := collectListedCategories(databases, opts)
	results := make([]listedCategoryPattern, 0, len(patterns))
	for _, pattern := range patterns {
		result := listedCategoryPattern{Pattern: pattern.Pattern}
		for _, category := range categories {
			if categoryPatternMatches(pattern, category.Category) {
				result.Categories = append(result.Categories, category)
			}
		}
		results = append(results, result)
	}
	return results
}

func categoryPatternMatches(pattern compiledCategoryPattern, category string) bool {
	if pattern.Regex {
		return pattern.Expr != nil && pattern.Expr.MatchString(category)
	}
	return strings.Contains(strings.ToLower(category), pattern.Needle)
}

func collectListedCategories(databases []LoadedDatabase, opts listOptions) []listedCategory {
	categories := make([]listedCategory, 0)
	for _, db := range databases {
		for _, source := range db.Sources {
			categories = append(categories, listSourceCategories(db.Name, source, opts)...)
		}
	}
	return categories
}

func listSourceCategories(dbName string, source LoadedSource, opts listOptions) []listedCategory {
	categories := make([]listedCategory, 0)
	seen := make(map[string]struct{})
	needsSourceFallback := false

	appendCategory := func(category string) {
		category = strings.TrimSpace(category)
		if category == "" {
			return
		}
		key := strings.ToLower(category)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		categories = append(categories, listedCategory{
			Database: dbName,
			Source:   filepathSlash(source.Display),
			Format:   source.Format,
			Category: category,
		})
	}

	collectRuleCategory := func(subEntry string) {
		subEntry = strings.TrimSpace(subEntry)
		if subEntry == "" || isTechnicalRulesetName(subEntry) {
			needsSourceFallback = true
			return
		}
		appendCategory(subEntry)
	}

	for _, rule := range source.GeoIPRules {
		collectRuleCategory(rule.SubEntry)
	}
	for _, rule := range source.DomainRule {
		collectRuleCategory(rule.SubEntry)
	}
	if needsSourceFallback {
		appendCategory(sourceFallbackCategory(source))
	}
	if opts.IncludeMMDB {
		for _, category := range listMMDBCategoryNames(source) {
			appendCategory(category)
		}
	}

	return categories
}

func sourceFallbackCategory(source LoadedSource) string {
	candidates := sourceRulesetCandidates(source)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[len(candidates)-1]
}

func listMMDBCategoryNames(source LoadedSource) []string {
	if source.MMDB == nil || source.MMDB.Reader == nil {
		return nil
	}

	sourceHash, hasHash := fileSHA256Hex(source.Path)
	if hasHash {
		if names, ok := readValidMMDBCategoryNamesCache(source.Path, sourceHash); ok {
			return names
		}
		if doc, ok := readValidMMDBListCache(source.Path, sourceHash); ok {
			return doc.CategoryNames
		}
	}

	doc := buildMMDBListCache(source, sourceHash)
	if doc == nil {
		return nil
	}
	writeMMDBListCache(source.Path, doc)
	return doc.CategoryNames
}

func sortedMMDBCategoryNames(categories map[string][]string) []string {
	names := make([]string, 0, len(categories))
	for category := range categories {
		category = strings.TrimSpace(category)
		if category != "" {
			names = append(names, category)
		}
	}
	sort.Strings(names)
	return names
}

func filepathSlash(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func printListCategoryStartup(discovery DiscoveryResult, patternCount int) {
	mode := "current directory"
	if discovery.FromExeDir {
		mode = "executable directory fallback"
	}
	fmt.Printf("[geogrep] db_root=%s (%s) databases=%d patterns=%d\n", discovery.RootDir, mode, len(discovery.Databases), patternCount)
}

func printListAllCategoriesStartup(discovery DiscoveryResult) {
	mode := "current directory"
	if discovery.FromExeDir {
		mode = "executable directory fallback"
	}
	fmt.Printf("[geogrep] db_root=%s (%s) databases=%d\n", discovery.RootDir, mode, len(discovery.Databases))
}

func printListAllCategoriesResults(categories []listedCategory) {
	fmt.Println("\n[categories]")
	if len(categories) == 0 {
		fmt.Println("  no categories")
		return
	}

	currentDB := ""
	for _, category := range categories {
		if category.Database != currentDB {
			currentDB = category.Database
			fmt.Printf("  %s:\n", currentDB)
		}
		fmt.Printf("    - %s | %s | %s\n", category.Source, category.Format, category.Category)
	}
}

func printListCategoryResults(results []listedCategoryPattern) {
	for i, result := range results {
		fmt.Printf("\n[%d] category_pattern=%s\n", i+1, result.Pattern)
		if len(result.Categories) == 0 {
			fmt.Println("  no categories")
			continue
		}

		currentDB := ""
		for _, category := range result.Categories {
			if category.Database != currentDB {
				currentDB = category.Database
				fmt.Printf("  %s:\n", currentDB)
			}
			fmt.Printf("    - %s | %s | %s\n", category.Source, category.Format, category.Category)
		}
	}
}

func writeListCategoryJSON(path string, discovery DiscoveryResult, results []listedCategoryPattern, diags []Diagnostic) error {
	doc := buildListCategoryDocument(discovery, results, diags)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeCategoryListJSON(path string, discovery DiscoveryResult, categories []listedCategory, diags []Diagnostic) error {
	doc := buildCategoryListDocument(discovery, categories, diags)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func buildListCategoryDocument(discovery DiscoveryResult, results []listedCategoryPattern, diags []Diagnostic) ListCategoryDocument {
	return ListCategoryDocument{
		Metadata: ListCategoryMetadata{
			GeneratedAt:    time.Now().UTC(),
			DatabaseCount:  len(discovery.Databases),
			PatternCount:   len(results),
			UsedExecutable: discovery.FromExeDir,
		},
		Results:     results,
		Diagnostics: diags,
	}
}

func buildCategoryListDocument(discovery DiscoveryResult, categories []listedCategory, diags []Diagnostic) CategoryListDocument {
	return CategoryListDocument{
		Metadata: CategoryListMetadata{
			GeneratedAt:    time.Now().UTC(),
			DatabaseCount:  len(discovery.Databases),
			CategoryCount:  len(categories),
			UsedExecutable: discovery.FromExeDir,
		},
		Categories:  categories,
		Diagnostics: diags,
	}
}
