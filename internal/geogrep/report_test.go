package geogrep

import "testing"

func TestFormatMatchColumnsGroupedSourceUsesFileAsCategory(t *testing.T) {
	sourceCol, formatCol, categoryCol := formatMatchColumns("ios_rule_script", MatchRecord{
		Source: "ios_rule_script/Advertising.list",
		Format: "list",
		Rule:   "DOMAIN-SUFFIX,mtalk.google.com",
	})

	if sourceCol != "ios_rule_script" {
		t.Fatalf("source=%s want=ios_rule_script", sourceCol)
	}
	if formatCol != "list" {
		t.Fatalf("format=%s want=list", formatCol)
	}
	if categoryCol != "Advertising.list" {
		t.Fatalf("category=%s want=Advertising.list", categoryCol)
	}
}

func TestFormatMatchColumnsGroupedSourcePrefersFileOverSubEntry(t *testing.T) {
	sourceCol, formatCol, categoryCol := formatMatchColumns("foo", MatchRecord{
		Source:   "foo/bar.dat",
		Format:   "dat",
		SubEntry: "cn",
		Rule:     "suffix:google.com",
	})

	if sourceCol != "foo" {
		t.Fatalf("source=%s want=foo", sourceCol)
	}
	if formatCol != "dat" {
		t.Fatalf("format=%s want=dat", formatCol)
	}
	if categoryCol != "bar.dat" {
		t.Fatalf("category=%s want=bar.dat", categoryCol)
	}
}

func TestFormatMatchColumnsStandaloneSourceKeepsSubEntry(t *testing.T) {
	sourceCol, formatCol, categoryCol := formatMatchColumns("geosite.dat", MatchRecord{
		Source:   "geosite.dat",
		Format:   "dat",
		SubEntry: "google",
		Rule:     "suffix:google.com",
	})

	if sourceCol != "geosite.dat" {
		t.Fatalf("source=%s want=geosite.dat", sourceCol)
	}
	if formatCol != "dat" {
		t.Fatalf("format=%s want=dat", formatCol)
	}
	if categoryCol != "google" {
		t.Fatalf("category=%s want=google", categoryCol)
	}
}
