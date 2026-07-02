package geogrep

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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

func TestListCategoriesMatchesPlainTextCaseInsensitive(t *testing.T) {
	results, err := listCategories([]LoadedDatabase{{
		Name: "geoip.dat",
		Sources: []LoadedSource{{
			Display: "geoip.dat",
			Format:  "dat",
			GeoIPRules: []GeoIPRule{{
				SubEntry: "CN",
				Rule:     "1.0.1.0/24",
				Prefix:   netip.MustParsePrefix("1.0.1.0/24"),
			}, {
				SubEntry: "US",
				Rule:     "1.1.1.0/24",
				Prefix:   netip.MustParsePrefix("1.1.1.0/24"),
			}},
		}},
	}, {
		Name: "geosite.dat",
		Sources: []LoadedSource{{
			Display: "geosite.dat",
			Format:  "dat",
			DomainRule: []DomainRule{{
				SubEntry: "apple-cn",
				Rule:     "domain:apple.com.cn",
				Kind:     DomainExact,
				Value:    "apple.com.cn",
			}},
		}},
	}}, []string{"cn"})
	if err != nil {
		t.Fatalf("listCategories returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("results=%d want=1", len(results))
	}
	if len(results[0].Categories) != 2 {
		t.Fatalf("categories=%#v want CN and apple-cn", results[0].Categories)
	}
	if results[0].Categories[0].Database != "geoip.dat" || results[0].Categories[0].Category != "CN" {
		t.Fatalf("first category=%#v want geoip.dat CN", results[0].Categories[0])
	}
	if results[0].Categories[1].Database != "geosite.dat" || results[0].Categories[1].Category != "apple-cn" {
		t.Fatalf("second category=%#v want geosite.dat apple-cn", results[0].Categories[1])
	}
}

func TestListCategoriesMatchesRegexOnlyWhenEnabled(t *testing.T) {
	databases := []LoadedDatabase{{
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
	}}

	results, err := listCategories(databases, []string{"^cn$"})
	if err != nil {
		t.Fatalf("listCategories returned error: %v", err)
	}
	if len(results) != 1 || len(results[0].Categories) != 0 {
		t.Fatalf("plain text regex-looking search=%#v want no literal match", results)
	}

	results, err = listCategoriesWithOptions(databases, []string{"^cn$"}, listOptions{Regex: true})
	if err != nil {
		t.Fatalf("listCategoriesWithOptions returned error: %v", err)
	}
	if len(results) != 1 || len(results[0].Categories) != 1 {
		t.Fatalf("regex search=%#v want one category", results)
	}
}

func TestListCategoriesDeduplicatesCategoryPerSource(t *testing.T) {
	results, err := listCategories([]LoadedDatabase{{
		Name: "geosite.dat",
		Sources: []LoadedSource{{
			Display: "geosite.dat",
			Format:  "dat",
			DomainRule: []DomainRule{{
				SubEntry: "google",
				Rule:     "domain:google.com",
				Kind:     DomainExact,
				Value:    "google.com",
			}, {
				SubEntry: "google",
				Rule:     "domain_suffix:google.com",
				Kind:     DomainSuffix,
				Value:    "google.com",
			}},
		}},
	}}, []string{"google"})
	if err != nil {
		t.Fatalf("listCategories returned error: %v", err)
	}

	if len(results) != 1 || len(results[0].Categories) != 1 {
		t.Fatalf("results=%#v want one deduplicated category", results)
	}
}

func TestListCategoriesUsesSourceStemForSparseSource(t *testing.T) {
	results, err := listCategories([]LoadedDatabase{{
		Name: "lan",
		Sources: []LoadedSource{{
			Display: "lan/private.list",
			Format:  "list",
			DomainRule: []DomainRule{{
				Rule:  "DOMAIN,router.lan",
				Kind:  DomainExact,
				Value: "router.lan",
			}},
		}},
	}}, []string{"private"})
	if err != nil {
		t.Fatalf("listCategories returned error: %v", err)
	}

	if len(results) != 1 || len(results[0].Categories) != 1 {
		t.Fatalf("results=%#v want one sparse source category", results)
	}
	if results[0].Categories[0].Category != "private" {
		t.Fatalf("category=%s want=private", results[0].Categories[0].Category)
	}
}

func TestListAllCategoriesReturnsEveryCategory(t *testing.T) {
	results := listAllCategories([]LoadedDatabase{{
		Name: "geoip.dat",
		Sources: []LoadedSource{{
			Display: "geoip.dat",
			Format:  "dat",
			GeoIPRules: []GeoIPRule{{
				SubEntry: "CN",
				Rule:     "1.0.1.0/24",
				Prefix:   netip.MustParsePrefix("1.0.1.0/24"),
			}, {
				SubEntry: "US",
				Rule:     "1.1.1.0/24",
				Prefix:   netip.MustParsePrefix("1.1.1.0/24"),
			}},
		}},
	}, {
		Name: "geosite.dat",
		Sources: []LoadedSource{{
			Display: "geosite.dat",
			Format:  "dat",
			DomainRule: []DomainRule{{
				SubEntry: "apple-cn",
				Rule:     "domain:apple.com.cn",
				Kind:     DomainExact,
				Value:    "apple.com.cn",
			}},
		}},
	}})

	if len(results) != 3 {
		t.Fatalf("categories=%#v want CN, US, apple-cn", results)
	}
	if results[0].Category != "CN" || results[1].Category != "US" || results[2].Category != "apple-cn" {
		t.Fatalf("categories=%#v want CN, US, apple-cn", results)
	}
}

func TestListAllCategoriesBuildsJSONDocument(t *testing.T) {
	discovery := DiscoveryResult{
		Databases:  []DiscoveredDatabase{{Name: "geoip.dat"}},
		FromExeDir: true,
	}
	categories := []listedCategory{{
		Database: "geoip.dat",
		Source:   "geoip.dat",
		Format:   "dat",
		Category: "CN",
	}}

	doc := buildCategoryListDocument(discovery, categories, nil)

	if doc.Metadata.DatabaseCount != 1 {
		t.Fatalf("database_count=%d want=1", doc.Metadata.DatabaseCount)
	}
	if doc.Metadata.CategoryCount != 1 {
		t.Fatalf("category_count=%d want=1", doc.Metadata.CategoryCount)
	}
	if !doc.Metadata.UsedExecutable {
		t.Fatal("expected executable fallback metadata")
	}
	if len(doc.Categories) != 1 || doc.Categories[0].Category != "CN" {
		t.Fatalf("categories=%#v want CN", doc.Categories)
	}
}

func TestListCategoriesUsesListMMDBOptions(t *testing.T) {
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

	mixedDatabases := []LoadedDatabase{{
		Name:    "geoip.mmdb",
		Sources: []LoadedSource{source},
	}, {
		Name: "geosite.dat",
		Sources: []LoadedSource{{
			Display: "geosite.dat",
			Format:  "dat",
			DomainRule: []DomainRule{{
				SubEntry: "google",
				Rule:     "domain:google.com",
				Kind:     DomainExact,
				Value:    "google.com",
			}},
		}},
	}}

	results, err := listCategories(mixedDatabases, []string{"cn"})
	if err != nil {
		t.Fatalf("listCategories returned error: %v", err)
	}
	if len(results) != 1 || len(results[0].Categories) != 0 {
		t.Fatalf("default mixed results=%#v want no MMDB category", results)
	}

	results, err = listCategoriesWithOptions(mixedDatabases, []string{"cn"}, listOptions{IncludeMMDB: true})
	if err != nil {
		t.Fatalf("listCategories returned error: %v", err)
	}
	if len(results) != 1 || len(results[0].Categories) != 1 {
		t.Fatalf("explicit include results=%#v want one MMDB category", results)
	}
	if results[0].Categories[0].Category != "CN" {
		t.Fatalf("category=%s want=CN", results[0].Categories[0].Category)
	}

	results, err = listCategories([]LoadedDatabase{{
		Name:    "geoip.mmdb",
		Sources: []LoadedSource{source},
	}}, []string{"cn"})
	if err != nil {
		t.Fatalf("listCategories returned error: %v", err)
	}
	if len(results) != 1 || len(results[0].Categories) != 1 {
		t.Fatalf("MMDB-only results=%#v want one auto-included MMDB category", results)
	}
	cacheData, err := os.ReadFile(mmdbListCachePath(mmdbPath))
	if err != nil {
		t.Fatalf("read generated category cache: %v", err)
	}
	var doc mmdbListCacheDocument
	if err := json.Unmarshal(cacheData, &doc); err != nil {
		t.Fatalf("unmarshal generated category cache: %v", err)
	}
	if len(doc.CategoryNames) != 1 || doc.CategoryNames[0] != "CN" {
		t.Fatalf("category_names=%v want [CN]", doc.CategoryNames)
	}
}

func TestListAllCategoriesUsesListMMDBOptions(t *testing.T) {
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

	mixedDatabases := []LoadedDatabase{{
		Name:    "geoip.mmdb",
		Sources: []LoadedSource{source},
	}, {
		Name: "geosite.dat",
		Sources: []LoadedSource{{
			Display: "geosite.dat",
			Format:  "dat",
			DomainRule: []DomainRule{{
				SubEntry: "google",
				Rule:     "domain:google.com",
				Kind:     DomainExact,
				Value:    "google.com",
			}},
		}},
	}}

	results := listAllCategories(mixedDatabases)
	if len(results) != 1 {
		t.Fatalf("default mixed categories=%#v want only non-MMDB category", results)
	}
	if results[0].Category != "google" {
		t.Fatalf("category=%s want=google", results[0].Category)
	}

	results = listAllCategoriesWithOptions(mixedDatabases, listOptions{IncludeMMDB: true})
	if len(results) != 2 {
		t.Fatalf("explicit include categories=%#v want MMDB plus non-MMDB categories", results)
	}
	if results[0].Category != "CN" || results[1].Category != "google" {
		t.Fatalf("categories=%#v want CN then google", results)
	}

	results = listAllCategories([]LoadedDatabase{{
		Name:    "geoip.mmdb",
		Sources: []LoadedSource{source},
	}})
	if len(results) != 1 {
		t.Fatalf("MMDB-only categories=%#v want auto-included MMDB category", results)
	}
	if results[0].Category != "CN" {
		t.Fatalf("category=%s want=CN", results[0].Category)
	}
}

func TestListCategoriesRejectsInvalidRegex(t *testing.T) {
	_, err := listCategoriesWithOptions(nil, []string{"["}, listOptions{Regex: true})
	if err == nil {
		t.Fatal("expected invalid regex error")
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
	if len(doc.CategoryNames) != 2 || doc.CategoryNames[0] != "CN" || doc.CategoryNames[1] != "US" {
		t.Fatalf("category_names=%v want [CN US]", doc.CategoryNames)
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

func TestListCategoriesUsesMMDBCacheCategoryNames(t *testing.T) {
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
		Schema:        mmdbListCacheSchema,
		Source:        "geoip.mmdb",
		SourceSHA:     sourceHash,
		CategoryNames: []string{"ZZ"},
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

	results, err := listCategoriesWithOptions([]LoadedDatabase{{
		Name:    "geoip.mmdb",
		Sources: []LoadedSource{source},
	}}, []string{"zz"}, listOptions{IncludeMMDB: true})
	if err != nil {
		t.Fatalf("listCategories returned error: %v", err)
	}
	if len(results) != 1 || len(results[0].Categories) != 1 {
		t.Fatalf("results=%#v want one cached category-name match", results)
	}
	if results[0].Categories[0].Category != "ZZ" {
		t.Fatalf("category=%s want cached category name ZZ", results[0].Categories[0].Category)
	}
}

func TestReadValidMMDBCategoryNamesCache(t *testing.T) {
	tmp := t.TempDir()
	mmdbPath := filepath.Join(tmp, "geoip.mmdb")
	if err := os.WriteFile(mmdbPath, []byte("not a real mmdb for hash-only cache test"), 0o644); err != nil {
		t.Fatal(err)
	}
	sourceHash, ok := fileSHA256Hex(mmdbPath)
	if !ok {
		t.Fatal("failed to hash test mmdb")
	}
	cacheData := []byte(fmt.Sprintf(`{"schema":%q,"source":"geoip.mmdb","source_sha256":%q,"category_names":["US","CN","cn",""]}`, mmdbListCacheSchema, sourceHash))
	if err := os.WriteFile(mmdbListCachePath(mmdbPath), cacheData, 0o644); err != nil {
		t.Fatal(err)
	}

	names, ok := readValidMMDBCategoryNamesCache(mmdbPath, sourceHash)
	if !ok {
		t.Fatal("expected category_names cache to be valid")
	}
	if len(names) != 2 || names[0] != "CN" || names[1] != "US" {
		t.Fatalf("names=%v want [CN US]", names)
	}
}

func TestReadValidMMDBListCacheDerivesLegacyCategoryNames(t *testing.T) {
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
	cacheData := []byte(fmt.Sprintf(`{"schema":%q,"source":"geoip.mmdb","source_sha256":%q,"categories":{"US":["1.1.1.0/24"],"CN":["1.0.1.0/24"]}}`, mmdbListCacheSchema, sourceHash))
	if err := os.WriteFile(mmdbListCachePath(mmdbPath), cacheData, 0o644); err != nil {
		t.Fatal(err)
	}

	doc, ok := readValidMMDBListCache(mmdbPath, sourceHash)
	if !ok {
		t.Fatal("expected legacy cache to be valid")
	}
	if len(doc.CategoryNames) != 2 || doc.CategoryNames[0] != "CN" || doc.CategoryNames[1] != "US" {
		t.Fatalf("category_names=%v want [CN US]", doc.CategoryNames)
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

func TestIsMMDBListCacheFileUsesBoundedSchemaProbe(t *testing.T) {
	tmp := t.TempDir()
	cachePath := filepath.Join(tmp, "geoip.json")
	cacheData := []byte(fmt.Sprintf(`{"schema":%q,"source_sha256":"abc","categories":{}}`, mmdbListCacheSchema))
	if err := os.WriteFile(cachePath, cacheData, 0o644); err != nil {
		t.Fatal(err)
	}
	if !isMMDBListCacheFile(cachePath) {
		t.Fatal("expected generated cache to be detected")
	}

	rulesPath := filepath.Join(tmp, "rules.json")
	largeRule := `{"version":1,"rules":[{"domain":"` + strings.Repeat("a", maxMMDBListCacheProbeBytes*2) + `.example"}]}`
	if err := os.WriteFile(rulesPath, []byte(largeRule), 0o644); err != nil {
		t.Fatal(err)
	}
	if isMMDBListCacheFile(rulesPath) {
		t.Fatal("large normal ruleset should not be detected as generated cache")
	}
}
