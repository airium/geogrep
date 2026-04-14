package geogrep

import "testing"

func TestKeywordMatchesOnlyRuleContent(t *testing.T) {
	source := LoadedSource{
		Display: "test.dat",
		Format:  "dat",
		DomainRule: []DomainRule{
			{SubEntry: "google", Rule: "suffix:0emm.com", Value: "0emm.com", Kind: DomainSuffix},
			{SubEntry: "other", Rule: "suffix:google.com", Value: "google.com", Kind: DomainSuffix},
		},
	}

	query := Query{Kind: QueryKeyword, Normalized: "google"}
	matches := matchSource(query, "testdb", source)
	if len(matches) != 1 {
		t.Fatalf("match count=%d want=1", len(matches))
	}
	if matches[0].Rule != "suffix:google.com" {
		t.Fatalf("rule=%s want=suffix:google.com", matches[0].Rule)
	}
}
