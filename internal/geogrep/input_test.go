package geogrep

import "testing"

func TestClassifyAuto(t *testing.T) {
	tests := []struct {
		in   string
		kind QueryKind
	}{
		{"1.1.1.1", QueryIP},
		{"2001:db8::1", QueryIP},
		{"1.1.1.0/24", QueryCIDR},
		{"example.com", QueryDomain},
		{"shopping keyword", QueryKeyword},
	}

	for _, tt := range tests {
		query, err := classifyInput(0, RawInput{Value: tt.in, Force: ForceAuto})
		if err != nil {
			t.Fatalf("classifyInput(%q) error: %v", tt.in, err)
		}
		if query.Kind != tt.kind {
			t.Fatalf("classifyInput(%q) kind=%s want=%s", tt.in, query.Kind, tt.kind)
		}
	}
}

func TestClassifyForcedIPv4(t *testing.T) {
	query, err := classifyInput(0, RawInput{Value: "8.8.8.8", Force: ForceIPv4})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if query.Kind != QueryIP {
		t.Fatalf("kind=%s want=%s", query.Kind, QueryIP)
	}

	if _, err := classifyInput(0, RawInput{Value: "example.com", Force: ForceIPv4}); err == nil {
		t.Fatal("expected error for non-ipv4 input")
	}
}

func TestClassifyForcedDomainStrict(t *testing.T) {
	query, err := classifyInput(0, RawInput{Value: "example.com", Force: ForceDomain})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if query.Kind != QueryDomain {
		t.Fatalf("kind=%s want=%s", query.Kind, QueryDomain)
	}

	if _, err := classifyInput(0, RawInput{Value: "google", Force: ForceDomain}); err == nil {
		t.Fatal("expected error for non-domain -d input")
	}
}

func TestClassifyForcedKeyword(t *testing.T) {
	query, err := classifyInput(0, RawInput{Value: "google", Force: ForceKeyword})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if query.Kind != QueryKeyword {
		t.Fatalf("kind=%s want=%s", query.Kind, QueryKeyword)
	}
}
