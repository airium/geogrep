package geogrep

import "testing"

func TestParseCLIArgsVersionSubcommand(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"version"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "version" {
		t.Fatalf("command=%s want=version", cfg.Command)
	}
	if cfg.Verbose != 0 {
		t.Fatalf("verbose=%d want=0", cfg.Verbose)
	}
}

func TestParseCLIArgsFindRuleVerbose(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"find-rule", "-v", "google.com"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "find-rule" {
		t.Fatalf("command=%s want=find-rule", cfg.Command)
	}
	if cfg.Verbose != 1 {
		t.Fatalf("verbose=%d want=1", cfg.Verbose)
	}
	if !cfg.ReportEmpty {
		t.Fatal("expected ReportEmpty=true when verbose >= 1")
	}
}

func TestParseCLIArgsFindRuleShortcut(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"fr", "-vv", "google.com"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "find-rule" {
		t.Fatalf("command=%s want=find-rule", cfg.Command)
	}
	if cfg.Verbose != 2 {
		t.Fatalf("verbose=%d want=2", cfg.Verbose)
	}
}

func TestParseCLIArgsFindRuleVerboseLevel(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"find-rule", "--verbose=3", "google.com"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Verbose != 3 {
		t.Fatalf("verbose=%d want=3", cfg.Verbose)
	}
}

func TestParseCLIArgsListRule(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"list-rule", "--include-mmdb", "--json", "/tmp/list.json", "-db", "/tmp/db", "lan", "private"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "list-rule" {
		t.Fatalf("command=%s want=list-rule", cfg.Command)
	}
	if cfg.DBDir != "/tmp/db" {
		t.Fatalf("db=%s want=/tmp/db", cfg.DBDir)
	}
	if cfg.JSONPath != "/tmp/list.json" {
		t.Fatalf("json=%s want=/tmp/list.json", cfg.JSONPath)
	}
	if !cfg.IncludeMMDB {
		t.Fatal("expected IncludeMMDB=true")
	}
	if len(cfg.Rulesets) != 2 || cfg.Rulesets[0] != "lan" || cfg.Rulesets[1] != "private" {
		t.Fatalf("rulesets=%v want [lan private]", cfg.Rulesets)
	}
}

func TestParseCLIArgsListRuleShortcut(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"lr", "private"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "list-rule" {
		t.Fatalf("command=%s want=list-rule", cfg.Command)
	}
	if len(cfg.Rulesets) != 1 || cfg.Rulesets[0] != "private" {
		t.Fatalf("rulesets=%v want [private]", cfg.Rulesets)
	}
}

func TestParseCLIArgsListRuleRequiresRuleset(t *testing.T) {
	_, err := parseCLIArgs([]string{"list-rule", "-db", "/tmp/db"})
	if err == nil {
		t.Fatal("expected error for missing ruleset")
	}
}

func TestParseCLIArgsFindCategory(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"find-category", "--regex", "--include-mmdb", "--json", "/tmp/categories.json", "-db", "/tmp/db", "cn", "^google$"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "find-category" {
		t.Fatalf("command=%s want=find-category", cfg.Command)
	}
	if cfg.DBDir != "/tmp/db" {
		t.Fatalf("db=%s want=/tmp/db", cfg.DBDir)
	}
	if cfg.JSONPath != "/tmp/categories.json" {
		t.Fatalf("json=%s want=/tmp/categories.json", cfg.JSONPath)
	}
	if !cfg.IncludeMMDB {
		t.Fatal("include_mmdb should be true")
	}
	if !cfg.CategoryRegex {
		t.Fatal("category regex should be true")
	}
	if len(cfg.CategoryPatterns) != 2 || cfg.CategoryPatterns[0] != "cn" || cfg.CategoryPatterns[1] != "^google$" {
		t.Fatalf("category patterns=%v want [cn ^google$]", cfg.CategoryPatterns)
	}
}

func TestParseCLIArgsFindCategoryShortcut(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"fc", "^cn$"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "find-category" {
		t.Fatalf("command=%s want=find-category", cfg.Command)
	}
	if len(cfg.CategoryPatterns) != 1 || cfg.CategoryPatterns[0] != "^cn$" {
		t.Fatalf("category patterns=%v want [^cn$]", cfg.CategoryPatterns)
	}
}

func TestParseCLIArgsFindCategoryRequiresPattern(t *testing.T) {
	_, err := parseCLIArgs([]string{"find-category", "-db", "/tmp/db"})
	if err == nil {
		t.Fatal("expected error for missing category search value")
	}
}

func TestParseCLIArgsListCategory(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"list-category", "--include-mmdb", "--json", "/tmp/categories.json", "-db", "/tmp/db"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "list-category" {
		t.Fatalf("command=%s want=list-category", cfg.Command)
	}
	if cfg.DBDir != "/tmp/db" {
		t.Fatalf("db=%s want=/tmp/db", cfg.DBDir)
	}
	if cfg.JSONPath != "/tmp/categories.json" {
		t.Fatalf("json=%s want=/tmp/categories.json", cfg.JSONPath)
	}
	if !cfg.IncludeMMDB {
		t.Fatal("include_mmdb should be true")
	}
}

func TestParseCLIArgsListCategoryShortcut(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"lc"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "list-category" {
		t.Fatalf("command=%s want=list-category", cfg.Command)
	}
}

func TestParseCLIArgsListCategoryRejectsPattern(t *testing.T) {
	_, err := parseCLIArgs([]string{"list-category", "cn"})
	if err == nil {
		t.Fatal("expected error for unexpected positional category")
	}
}

func TestParseCLIArgsWebDefaults(t *testing.T) {
	t.Setenv("GEOGREP_ENV", "")

	cfg, err := parseCLIArgs([]string{"web"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "web" {
		t.Fatalf("command=%s want=web", cfg.Command)
	}
	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Fatalf("listen=%s want=127.0.0.1:8080", cfg.ListenAddr)
	}
	if cfg.ReportEmpty {
		t.Fatal("ReportEmpty should be false by default")
	}
}

func TestParseCLIArgsWebDevelopmentDefault(t *testing.T) {
	t.Setenv("GEOGREP_ENV", "development")

	cfg, err := parseCLIArgs([]string{"web"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:8080" {
		t.Fatalf("listen=%s want=0.0.0.0:8080", cfg.ListenAddr)
	}
}

func TestParseCLIArgsWebFlags(t *testing.T) {
	t.Setenv("GEOGREP_ENV", "development")

	cfg, err := parseCLIArgs([]string{
		"web",
		"-db", "/tmp/db",
		"--listen", "127.0.0.1:9000",
		"--webui", "./ui",
		"--api-only",
		"-vv",
	})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.DBDir != "/tmp/db" {
		t.Fatalf("db=%s want=/tmp/db", cfg.DBDir)
	}
	if cfg.ListenAddr != "127.0.0.1:9000" {
		t.Fatalf("listen=%s want=127.0.0.1:9000", cfg.ListenAddr)
	}
	if cfg.WebUIPath != "./ui" {
		t.Fatalf("webui=%s want=./ui", cfg.WebUIPath)
	}
	if !cfg.APIOnly {
		t.Fatal("expected APIOnly=true")
	}
	if cfg.Verbose != 2 {
		t.Fatalf("verbose=%d want=2", cfg.Verbose)
	}
	if !cfg.ReportEmpty {
		t.Fatal("expected ReportEmpty=true when verbose >= 1")
	}
}

func TestParseCLIArgsWebInvalidListen(t *testing.T) {
	_, err := parseCLIArgs([]string{"web", "--listen", "127.0.0.1"})
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

func TestParseCLIArgsConvertFlags(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"convert", "-i", "in.dat", "-o", "out.json", "--to", "json"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "convert" {
		t.Fatalf("command=%s want=convert", cfg.Command)
	}
	if cfg.ConvertIn != "in.dat" {
		t.Fatalf("input=%s want=in.dat", cfg.ConvertIn)
	}
	if cfg.ConvertOut != "out.json" {
		t.Fatalf("output=%s want=out.json", cfg.ConvertOut)
	}
	if cfg.ConvertTo != "json" {
		t.Fatalf("to=%s want=json", cfg.ConvertTo)
	}
}

func TestParseCLIArgsConvertPositionals(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"convert", "in.list", "out.srs"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.ConvertIn != "in.list" {
		t.Fatalf("input=%s want=in.list", cfg.ConvertIn)
	}
	if cfg.ConvertOut != "out.srs" {
		t.Fatalf("output=%s want=out.srs", cfg.ConvertOut)
	}
}

func TestParseCLIArgsConvertRequiresOutput(t *testing.T) {
	_, err := parseCLIArgs([]string{"convert", "-i", "in.list"})
	if err == nil {
		t.Fatal("expected error for missing output")
	}
}

func TestParseCLIArgsMissingSubcommand(t *testing.T) {
	_, err := parseCLIArgs([]string{})
	if err == nil {
		t.Fatal("expected error for missing subcommand")
	}
}

func TestParseCLIArgsUnknownSubcommand(t *testing.T) {
	_, err := parseCLIArgs([]string{"noop"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}
