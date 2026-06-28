package geogrep

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConvertTextToJSON(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "rules.list")
	out := filepath.Join(tmp, "rules.json")
	writeTestFile(t, in, "DOMAIN,example.com\nDOMAIN-SUFFIX,google.com\nIP-CIDR,1.1.1.0/24\n")

	summary, err := convertDatabases(CLIConfig{ConvertIn: in, ConvertOut: out})
	if err != nil {
		t.Fatalf("convertDatabases error: %v", err)
	}
	if summary.Format != convertFormatJSON {
		t.Fatalf("format=%s want=json", summary.Format)
	}
	if summary.GeoIPCount != 1 || summary.DomainCount != 2 {
		t.Fatalf("counts geoip=%d domains=%d want 1/2", summary.GeoIPCount, summary.DomainCount)
	}

	var doc convertDocument
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		t.Fatalf("unmarshal converted json: %v", err)
	}
	if doc.Version != 1 {
		t.Fatalf("version=%d want=1", doc.Version)
	}
	if len(doc.Rules) != 1 {
		t.Fatalf("rule groups=%d want=1", len(doc.Rules))
	}
	rule := doc.Rules[0]
	if rule.Category != "default" {
		t.Fatalf("category=%q want=default", rule.Category)
	}
	if got := firstString(rule.Domain); got != "example.com" {
		t.Fatalf("domain=%q want=example.com", got)
	}
	if got := firstString(rule.DomainSuffix); got != "google.com" {
		t.Fatalf("suffix=%q want=google.com", got)
	}
	if got := firstString(rule.IPCIDR); got != "1.1.1.0/24" {
		t.Fatalf("ip_cidr=%q want=1.1.1.0/24", got)
	}
}

func TestConvertDomainJSONToDAT(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "rules.json")
	out := filepath.Join(tmp, "geosite.dat")
	writeTestFile(t, in, `{"version":1,"rules":[{"category":"test","domain":["example.com"],"domain_suffix":["google.com"],"domain_keyword":["ads"],"domain_regex":["^cdn\\.example\\.com$"]}]}`)

	if _, err := convertDatabases(CLIConfig{ConvertIn: in, ConvertOut: out}); err != nil {
		t.Fatalf("convertDatabases error: %v", err)
	}

	source := LoadedSource{Path: out, Display: "geosite.dat"}
	if err := loadDAT(&source); err != nil {
		t.Fatalf("loadDAT converted output: %v", err)
	}
	if source.Format != "dat" {
		t.Fatalf("format=%s want=dat", source.Format)
	}
	if len(source.DomainRule) != 4 {
		t.Fatalf("domain rules=%d want=4", len(source.DomainRule))
	}
}

func TestConvertIPJSONToSRS(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "rules.json")
	out := filepath.Join(tmp, "geoip.srs")
	writeTestFile(t, in, `{"version":1,"rules":[{"category":"test","ip_cidr":["1.1.1.0/24","2001:db8::/32"]}]}`)

	if _, err := convertDatabases(CLIConfig{ConvertIn: in, ConvertOut: out}); err != nil {
		t.Fatalf("convertDatabases error: %v", err)
	}

	source := LoadedSource{Path: out, Display: "geoip.srs"}
	if err := loadSRS(&source); err != nil {
		t.Fatalf("loadSRS converted output: %v", err)
	}
	if source.Format != "srs" {
		t.Fatalf("format=%s want=srs", source.Format)
	}
	if len(source.GeoIPRules) != 2 {
		t.Fatalf("geoip rules=%d want=2", len(source.GeoIPRules))
	}
}

func TestConvertDomainJSONToMRS(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "rules.json")
	out := filepath.Join(tmp, "domain.mrs")
	writeTestFile(t, in, `{"version":1,"rules":[{"category":"test","domain":["example.com"],"domain_suffix":["google.com"]}]}`)

	if _, err := convertDatabases(CLIConfig{ConvertIn: in, ConvertOut: out}); err != nil {
		t.Fatalf("convertDatabases error: %v", err)
	}

	source := LoadedSource{Path: out, Display: "domain.mrs"}
	if err := loadMRS(&source); err != nil {
		t.Fatalf("loadMRS converted output: %v", err)
	}
	if source.Format != "mrs" {
		t.Fatalf("format=%s want=mrs", source.Format)
	}
	if len(source.DomainRule) != 2 {
		t.Fatalf("domain rules=%d want=2", len(source.DomainRule))
	}
}

func TestConvertDomainJSONToSingGeo(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "rules.json")
	out := filepath.Join(tmp, "geosite.db")
	writeTestFile(t, in, `{"version":1,"rules":[{"category":"test","domain":["example.com"],"domain_suffix":["google.com"],"domain_keyword":["ads"],"domain_regex":["^cdn\\.example\\.com$"]}]}`)

	if _, err := convertDatabases(CLIConfig{ConvertIn: in, ConvertOut: out, ConvertTo: "singgeo"}); err != nil {
		t.Fatalf("convertDatabases error: %v", err)
	}

	source := LoadedSource{Path: out, Display: "geosite.db"}
	if err := loadSingGeoSite(&source); err != nil {
		t.Fatalf("loadSingGeoSite converted output: %v", err)
	}
	if source.Format != "singgeo" {
		t.Fatalf("format=%s want=singgeo", source.Format)
	}
	if len(source.DomainRule) != 4 {
		t.Fatalf("domain rules=%d want=4", len(source.DomainRule))
	}
}

func TestConvertIPJSONToMMDB(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "rules.json")
	out := filepath.Join(tmp, "geoip.mmdb")
	writeTestFile(t, in, `{"version":1,"rules":[{"category":"cf","ip_cidr":["1.1.1.0/24"]}]}`)

	if _, err := convertDatabases(CLIConfig{ConvertIn: in, ConvertOut: out}); err != nil {
		t.Fatalf("convertDatabases error: %v", err)
	}

	source := LoadedSource{Path: out, Display: "geoip.mmdb"}
	if err := loadMMDB(&source); err != nil {
		t.Fatalf("loadMMDB converted output: %v", err)
	}
	defer source.MMDB.Reader.Close()

	query, err := normalizeQueries([]RawInput{{Value: "1.1.1.1", Force: ForceAuto}})
	if err != nil {
		t.Fatal(err)
	}
	matches := matchSource(query[0], "geoip.mmdb", source)
	if len(matches) != 1 {
		t.Fatalf("matches=%d want=1", len(matches))
	}
}

func TestConvertRejectsMixedDATOutput(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "rules.json")
	out := filepath.Join(tmp, "mixed.dat")
	writeTestFile(t, in, `{"version":1,"rules":[{"category":"test","domain":["example.com"],"ip_cidr":["1.1.1.0/24"]}]}`)

	_, err := convertDatabases(CLIConfig{ConvertIn: in, ConvertOut: out})
	if err == nil {
		t.Fatal("expected mixed dat output error")
	}
}

func TestConvertRejectsUnsupportedTargetDomainKind(t *testing.T) {
	tmp := t.TempDir()
	in := filepath.Join(tmp, "rules.json")
	out := filepath.Join(tmp, "rules.srs")
	writeTestFile(t, in, `{"version":1,"rules":[{"category":"test","domain_wildcard":["*.example.com"]}]}`)

	_, err := convertDatabases(CLIConfig{ConvertIn: in, ConvertOut: out})
	if err == nil {
		t.Fatal("expected unsupported domain kind error")
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
