package geogrep

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/geo/encoding/v2raygeo"
	"google.golang.org/protobuf/proto"
)

func TestListRulesetsMatchesExactDATRuleset(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "geosite.dat")
	data, err := proto.Marshal(&v2raygeo.GeoSiteList{
		Entry: []*v2raygeo.GeoSite{
			{
				CountryCode: "lan",
				Domain: []*v2raygeo.Domain{{
					Type:  v2raygeo.Domain_Full,
					Value: "router.lan",
				}},
			},
			{
				CountryCode: "lancache",
				Domain: []*v2raygeo.Domain{{
					Type:  v2raygeo.Domain_Full,
					Value: "cache.lan",
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	discovery := DiscoveryResult{Databases: []DiscoveredDatabase{{
		Name: "geosite.dat",
		Sources: []DiscoveredSource{{
			Display: "geosite.dat",
			Path:    path,
		}},
	}}}
	databases, diagnostics := loadDatabases(discovery)
	defer closeDatabases(databases)
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics=%v want none", diagnostics)
	}

	results := listRulesets(databases, []string{"lan"})
	if len(results) != 1 {
		t.Fatalf("results=%d want=1", len(results))
	}
	if len(results[0].Rules) != 1 {
		t.Fatalf("rules=%d want=1", len(results[0].Rules))
	}
	rule := results[0].Rules[0]
	if rule.Ruleset != "lan" {
		t.Fatalf("ruleset=%s want=lan", rule.Ruleset)
	}
	if rule.Rule != "exact:router.lan" {
		t.Fatalf("rule=%s want=exact:router.lan", rule.Rule)
	}
}

func TestListRulesetsMatchesGeoIPCategoryCaseInsensitive(t *testing.T) {
	results := listRulesets([]LoadedDatabase{{
		Name: "geoip.dat",
		Sources: []LoadedSource{{
			Display: "geoip.dat",
			Format:  "dat",
			GeoIPRules: []GeoIPRule{{
				SubEntry: "CN",
				Rule:     "1.0.1.0/24",
				Prefix:   netip.MustParsePrefix("1.0.1.0/24"),
			}},
		}},
	}}, []string{"cn"})

	if len(results) != 1 {
		t.Fatalf("results=%d want=1", len(results))
	}
	if len(results[0].Rules) != 1 {
		t.Fatalf("rules=%d want=1", len(results[0].Rules))
	}
	if results[0].Rules[0].Ruleset != "CN" {
		t.Fatalf("ruleset=%s want=CN", results[0].Rules[0].Ruleset)
	}
	if results[0].Rules[0].Rule != "1.0.1.0/24" {
		t.Fatalf("rule=%s want=1.0.1.0/24", results[0].Rules[0].Rule)
	}
}

func TestListRulesetsMatchesSourceStemForTechnicalSubEntry(t *testing.T) {
	source := LoadedSource{
		Display: "private.srs",
		Format:  "srs",
		DomainRule: []DomainRule{{
			SubEntry: "rule[0]",
			Rule:     "domain_suffix:lan",
			Kind:     DomainSuffix,
			Value:    "lan",
		}},
	}

	results := listRulesets([]LoadedDatabase{{
		Name:    "private.srs",
		Sources: []LoadedSource{source},
	}}, []string{"private", "rule[0]"})

	if len(results) != 2 {
		t.Fatalf("results=%d want=2", len(results))
	}
	if len(results[0].Rules) != 1 {
		t.Fatalf("private rules=%d want=1", len(results[0].Rules))
	}
	if results[0].Rules[0].Ruleset != "private" {
		t.Fatalf("matched ruleset=%s want=private", results[0].Rules[0].Ruleset)
	}
	if len(results[1].Rules) != 1 {
		t.Fatalf("technical rules=%d want=1", len(results[1].Rules))
	}
	if results[1].Rules[0].Ruleset != "rule[0]" {
		t.Fatalf("matched ruleset=%s want=rule[0]", results[1].Rules[0].Ruleset)
	}
}

func TestListRulesetsDoesNotUseSourceStemForRealSubEntry(t *testing.T) {
	source := LoadedSource{
		Display: "geosite.dat",
		Format:  "dat",
		DomainRule: []DomainRule{{
			SubEntry: "google",
			Rule:     "exact:google.com",
			Kind:     DomainExact,
			Value:    "google.com",
		}},
	}

	results := listRulesets([]LoadedDatabase{{
		Name:    "geosite.dat",
		Sources: []LoadedSource{source},
	}}, []string{"geosite", "google"})

	if len(results) != 2 {
		t.Fatalf("results=%d want=2", len(results))
	}
	if len(results[0].Rules) != 0 {
		t.Fatalf("geosite rules=%d want=0", len(results[0].Rules))
	}
	if len(results[1].Rules) != 1 {
		t.Fatalf("google rules=%d want=1", len(results[1].Rules))
	}
}

func TestListRulesetsMatchesGroupedSparseFileRulesetName(t *testing.T) {
	source := LoadedSource{
		Display: "lan/rules.list",
		Format:  "list",
		DomainRule: []DomainRule{{
			Rule:  "DOMAIN,router.lan",
			Kind:  DomainExact,
			Value: "router.lan",
		}},
	}

	results := listRulesets([]LoadedDatabase{{
		Name:    "lan",
		Sources: []LoadedSource{source},
	}}, []string{"lan", "rules"})

	if len(results) != 2 {
		t.Fatalf("results=%d want=2", len(results))
	}
	if len(results[0].Rules) != 0 {
		t.Fatalf("lan rules=%d want=0", len(results[0].Rules))
	}
	if len(results[1].Rules) != 1 {
		t.Fatalf("rules rules=%d want=1", len(results[1].Rules))
	}
	if results[1].Rules[0].Ruleset != "rules" {
		t.Fatalf("matched ruleset=%s want=rules", results[1].Rules[0].Ruleset)
	}
}

func TestListRulesetsSkipsMMDBByDefault(t *testing.T) {
	tmp := t.TempDir()
	mmdbPath := filepath.Join(tmp, "geoip.mmdb")
	if err := writeConvertMMDB(mmdbPath, convertRuleSet{GeoIP: []GeoIPRule{{
		SubEntry: "CN",
		Rule:     "1.0.1.0/24",
		Prefix:   netip.MustParsePrefix("1.0.1.0/24"),
	}}}); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: mmdbPath, Display: "geoip.mmdb"}
	if err := loadMMDB(&source); err != nil {
		t.Fatal(err)
	}
	defer closeDatabases([]LoadedDatabase{{Sources: []LoadedSource{source}}})

	datSource := LoadedSource{
		Display: "geosite.dat",
		Format:  "dat",
		DomainRule: []DomainRule{{
			SubEntry: "private",
			Rule:     "exact:router.lan",
			Kind:     DomainExact,
			Value:    "router.lan",
		}},
	}

	results := listRulesets([]LoadedDatabase{{
		Name:    "mixed",
		Sources: []LoadedSource{source, datSource},
	}}, []string{"cn"})

	if len(results) != 1 {
		t.Fatalf("results=%d want=1", len(results))
	}
	if len(results[0].Rules) != 0 {
		t.Fatalf("rules=%d want=0", len(results[0].Rules))
	}
	if _, err := os.Stat(mmdbListCachePath(mmdbPath)); !os.IsNotExist(err) {
		t.Fatalf("cache should not be created without IncludeMMDB, stat err=%v", err)
	}
}

func TestListRulesetsAutoIncludesMMDBWhenOnlyLoadedDatabaseType(t *testing.T) {
	tmp := t.TempDir()
	mmdbPath := filepath.Join(tmp, "geoip.mmdb")
	if err := writeConvertMMDB(mmdbPath, convertRuleSet{GeoIP: []GeoIPRule{{
		SubEntry: "CN",
		Rule:     "1.0.1.0/24",
		Prefix:   netip.MustParsePrefix("1.0.1.0/24"),
	}}}); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: mmdbPath, Display: "geoip.mmdb"}
	if err := loadMMDB(&source); err != nil {
		t.Fatal(err)
	}
	defer closeDatabases([]LoadedDatabase{{Sources: []LoadedSource{source}}})

	results := listRulesets([]LoadedDatabase{{
		Name:    "geoip.mmdb",
		Sources: []LoadedSource{source},
	}}, []string{"cn"})

	if len(results) != 1 || len(results[0].Rules) != 1 {
		t.Fatalf("results=%#v want one auto-included MMDB rule", results)
	}
	if results[0].Rules[0].Rule != "1.0.1.0/24" {
		t.Fatalf("rule=%s want=1.0.1.0/24", results[0].Rules[0].Rule)
	}
}

func TestListRulesetsIncludesMMDBAndCreatesCache(t *testing.T) {
	tmp := t.TempDir()
	mmdbPath := filepath.Join(tmp, "geoip.mmdb")
	if err := writeConvertMMDB(mmdbPath, convertRuleSet{GeoIP: []GeoIPRule{{
		SubEntry: "CN",
		Rule:     "1.0.1.0/24",
		Prefix:   netip.MustParsePrefix("1.0.1.0/24"),
	}, {
		SubEntry: "US",
		Rule:     "1.1.1.0/24",
		Prefix:   netip.MustParsePrefix("1.1.1.0/24"),
	}}}); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: mmdbPath, Display: "geoip.mmdb"}
	if err := loadMMDB(&source); err != nil {
		t.Fatal(err)
	}
	defer closeDatabases([]LoadedDatabase{{Sources: []LoadedSource{source}}})

	results := listRulesetsWithOptions([]LoadedDatabase{{
		Name:    "geoip.mmdb",
		Sources: []LoadedSource{source},
	}}, []string{"cn"}, listOptions{IncludeMMDB: true})

	if len(results) != 1 || len(results[0].Rules) != 1 {
		t.Fatalf("results=%#v want one MMDB rule", results)
	}
	if results[0].Rules[0].Ruleset != "CN" {
		t.Fatalf("ruleset=%s want=CN", results[0].Rules[0].Ruleset)
	}
	if results[0].Rules[0].Rule != "1.0.1.0/24" {
		t.Fatalf("rule=%s want=1.0.1.0/24", results[0].Rules[0].Rule)
	}

	cacheData, err := os.ReadFile(mmdbListCachePath(mmdbPath))
	if err != nil {
		t.Fatalf("read generated cache: %v", err)
	}
	var doc mmdbListCacheDocument
	if err := json.Unmarshal(cacheData, &doc); err != nil {
		t.Fatalf("unmarshal generated cache: %v", err)
	}
	if doc.Schema != mmdbListCacheSchema {
		t.Fatalf("schema=%s want=%s", doc.Schema, mmdbListCacheSchema)
	}
	if doc.SourceSHA == "" {
		t.Fatal("expected source hash in cache")
	}
	if len(doc.Categories["CN"]) != 1 {
		t.Fatalf("CN cache entries=%v want one", doc.Categories["CN"])
	}
}

func TestListRulesetsUsesValidMMDBCache(t *testing.T) {
	tmp := t.TempDir()
	mmdbPath := filepath.Join(tmp, "geoip.mmdb")
	if err := writeConvertMMDB(mmdbPath, convertRuleSet{GeoIP: []GeoIPRule{{
		SubEntry: "CN",
		Rule:     "1.0.1.0/24",
		Prefix:   netip.MustParsePrefix("1.0.1.0/24"),
	}}}); err != nil {
		t.Fatal(err)
	}
	sourceHash, ok := fileSHA256Hex(mmdbPath)
	if !ok {
		t.Fatal("failed to hash test mmdb")
	}
	cache := mmdbListCacheDocument{
		Schema:    mmdbListCacheSchema,
		Source:    "geoip.mmdb",
		SourceSHA: sourceHash,
		Categories: map[string][]string{
			"CN": {"203.0.113.0/24"},
		},
	}
	cacheData, err := json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mmdbListCachePath(mmdbPath), cacheData, 0o644); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: mmdbPath, Display: "geoip.mmdb"}
	if err := loadMMDB(&source); err != nil {
		t.Fatal(err)
	}
	defer closeDatabases([]LoadedDatabase{{Sources: []LoadedSource{source}}})

	results := listRulesetsWithOptions([]LoadedDatabase{{
		Name:    "geoip.mmdb",
		Sources: []LoadedSource{source},
	}}, []string{"cn"}, listOptions{IncludeMMDB: true})

	if len(results) != 1 || len(results[0].Rules) != 1 {
		t.Fatalf("results=%#v want one cached MMDB rule", results)
	}
	if results[0].Rules[0].Rule != "203.0.113.0/24" {
		t.Fatalf("rule=%s want cached rule 203.0.113.0/24", results[0].Rules[0].Rule)
	}
}

func TestListRulesetsDoesNotOverwriteNonCacheJSON(t *testing.T) {
	tmp := t.TempDir()
	mmdbPath := filepath.Join(tmp, "geoip.mmdb")
	if err := writeConvertMMDB(mmdbPath, convertRuleSet{GeoIP: []GeoIPRule{{
		SubEntry: "CN",
		Rule:     "1.0.1.0/24",
		Prefix:   netip.MustParsePrefix("1.0.1.0/24"),
	}}}); err != nil {
		t.Fatal(err)
	}
	cachePath := mmdbListCachePath(mmdbPath)
	original := []byte(`{"version":1,"rules":["DOMAIN,example.com"]}`)
	if err := os.WriteFile(cachePath, original, 0o644); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: mmdbPath, Display: "geoip.mmdb"}
	if err := loadMMDB(&source); err != nil {
		t.Fatal(err)
	}
	defer closeDatabases([]LoadedDatabase{{Sources: []LoadedSource{source}}})

	results := listRulesetsWithOptions([]LoadedDatabase{{
		Name:    "geoip.mmdb",
		Sources: []LoadedSource{source},
	}}, []string{"cn"}, listOptions{IncludeMMDB: true})
	if len(results) != 1 || len(results[0].Rules) != 1 {
		t.Fatalf("results=%#v want one MMDB rule", results)
	}

	after, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatalf("non-cache json was overwritten: %s", after)
	}
}
