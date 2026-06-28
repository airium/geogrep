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

func TestAdGuardRuleMatchUsesMatcherSyntax(t *testing.T) {
	tests := []struct {
		rule   string
		domain string
		want   bool
	}{
		{rule: "||example.org^", domain: "example.org", want: true},
		{rule: "||example.org^", domain: "www.example.org", want: true},
		{rule: "||example.org^", domain: "example.org.cn", want: false},
		{rule: "|example.org^", domain: "example.org", want: true},
		{rule: "|example.org^", domain: "www.example.org", want: false},
		{rule: "example.org^", domain: "notexample.org", want: true},
		{rule: "example.org^", domain: "example.org.cn", want: false},
		{rule: "||example.org^$third-party", domain: "www.example.org", want: true},
		{rule: "@@||example.org^", domain: "www.example.org", want: false},
	}

	for _, tt := range tests {
		rule := DomainRule{Kind: DomainAdGuard, Value: tt.rule}
		if got := domainRuleMatches(rule, tt.domain); got != tt.want {
			t.Fatalf("domainRuleMatches(%q, %q)=%t want=%t", tt.rule, tt.domain, got, tt.want)
		}
	}
}
