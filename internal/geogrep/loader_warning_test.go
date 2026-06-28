package geogrep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTextRulesReportsInvalidTypedRules(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "rules.list")
	writeTestFile(t, path, "DOMAIN,example.com\nIP-CIDR,not-a-cidr\nDOMAIN-REGEX,[\n")

	databases, diagnostics := loadDatabases(DiscoveryResult{
		Databases: []DiscoveredDatabase{{
			Name: "rules.list",
			Sources: []DiscoveredSource{{
				Display: "rules.list",
				Path:    path,
			}},
		}},
	})
	defer closeDatabases(databases)

	if len(diagnostics) != 2 {
		t.Fatalf("diagnostics=%d want=2: %#v", len(diagnostics), diagnostics)
	}
	for _, diag := range diagnostics {
		if diag.Level != "warning" {
			t.Fatalf("diagnostic level=%s want=warning", diag.Level)
		}
		if diag.Scope != "rules.list" {
			t.Fatalf("diagnostic scope=%s want=rules.list", diag.Scope)
		}
	}
	if len(databases[0].Sources[0].DomainRule) != 1 {
		t.Fatalf("domain rules=%d want=1", len(databases[0].Sources[0].DomainRule))
	}
}

func TestConvertRejectsInvalidTypedRules(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "rules.list")
	out := filepath.Join(tmp, "rules.json")
	writeTestFile(t, in, "DOMAIN,example.com\nIP-CIDR,not-a-cidr\n")

	_, err := convertDatabases(CLIConfig{ConvertIn: in, ConvertOut: out})
	if err == nil {
		t.Fatal("expected conversion warning rejection")
	}
	if !strings.Contains(err.Error(), "failed to load clean input") {
		t.Fatalf("error=%q want clean input rejection", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("output exists after rejected conversion: %v", statErr)
	}
}
