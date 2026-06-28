package geogrep

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/geo/encoding/v2raygeo"
	"google.golang.org/protobuf/proto"
)

func TestLoadDATRejectsEntriesWithoutUsableGeoIPRules(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "geoip.dat")
	data, err := proto.Marshal(&v2raygeo.GeoIPList{
		Entry: []*v2raygeo.GeoIP{{
			CountryCode: "TEST",
			Cidr: []*v2raygeo.CIDR{{
				Ip:     []byte{1, 2, 3},
				Prefix: 24,
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: path}
	if err := loadDAT(&source); err == nil {
		t.Fatal("expected invalid dat payload error")
	}
	if len(source.GeoIPRules) != 0 || len(source.DomainRule) != 0 {
		t.Fatalf("loaded rules from invalid dat: geoip=%d domain=%d", len(source.GeoIPRules), len(source.DomainRule))
	}
}

func TestLoadDATRejectsEntriesWithoutUsableGeoSiteRules(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "geosite.dat")
	data, err := proto.Marshal(&v2raygeo.GeoSiteList{
		Entry: []*v2raygeo.GeoSite{{
			CountryCode: "test",
			Domain: []*v2raygeo.Domain{{
				Type:  v2raygeo.Domain_Full,
				Value: "",
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: path}
	if err := loadDAT(&source); err == nil {
		t.Fatal("expected invalid dat payload error")
	}
	if len(source.GeoIPRules) != 0 || len(source.DomainRule) != 0 {
		t.Fatalf("loaded rules from invalid dat: geoip=%d domain=%d", len(source.GeoIPRules), len(source.DomainRule))
	}
}

func TestLoadDATRejectsInvalidRegexOnlyGeoSiteRules(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "geosite.dat")
	data, err := proto.Marshal(&v2raygeo.GeoSiteList{
		Entry: []*v2raygeo.GeoSite{{
			CountryCode: "test",
			Domain: []*v2raygeo.Domain{{
				Type:  v2raygeo.Domain_Regex,
				Value: "[",
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: path}
	if err := loadDAT(&source); err == nil {
		t.Fatal("expected invalid dat payload error")
	}
	if len(source.DomainRule) != 0 {
		t.Fatalf("domain rules=%d want=0", len(source.DomainRule))
	}
}
