package geogrep

import (
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
