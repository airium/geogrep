package geogrep

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverDatabases(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "geosite.dat"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	subDir := filepath.Join(tmp, "shopping-sites")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "ads.list"), []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dbs, err := discoverDatabases(tmp)
	if err != nil {
		t.Fatalf("discoverDatabases error: %v", err)
	}
	if len(dbs) != 2 {
		t.Fatalf("database count=%d want=2", len(dbs))
	}

	if dbs[0].Name != "geosite.dat" {
		t.Fatalf("first database=%s want geosite.dat", dbs[0].Name)
	}
	if dbs[1].Name != "shopping-sites" {
		t.Fatalf("second database=%s want shopping-sites", dbs[1].Name)
	}
	if len(dbs[1].Sources) != 1 {
		t.Fatalf("shopping-sites sources=%d want=1", len(dbs[1].Sources))
	}
	if dbs[1].Sources[0].Display != "shopping-sites/ads.list" {
		t.Fatalf("source display=%s", dbs[1].Sources[0].Display)
	}
}
