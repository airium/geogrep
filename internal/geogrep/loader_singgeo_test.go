package geogrep

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSingGeoSite(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "geosite.db")

	var payload bytes.Buffer
	payload.WriteByte(1)
	writeVStringForTest(t, &payload, "google.com")

	var metadata bytes.Buffer
	metadata.WriteByte(0)
	writeUvarintForTest(t, &metadata, 1)
	writeVStringForTest(t, &metadata, "google")
	writeUvarintForTest(t, &metadata, 0)
	writeUvarintForTest(t, &metadata, 1)

	content := append(metadata.Bytes(), payload.Bytes()...)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: path}
	if err := loadSingGeoSite(&source); err != nil {
		t.Fatalf("loadSingGeoSite error: %v", err)
	}
	if source.Format != "singgeo" {
		t.Fatalf("format=%s want=singgeo", source.Format)
	}
	if len(source.DomainRule) != 1 {
		t.Fatalf("domain rule count=%d want=1", len(source.DomainRule))
	}
	if source.DomainRule[0].SubEntry != "google" {
		t.Fatalf("subentry=%s want=google", source.DomainRule[0].SubEntry)
	}
	if source.DomainRule[0].Rule != "suffix:google.com" {
		t.Fatalf("rule=%s want=suffix:google.com", source.DomainRule[0].Rule)
	}
}

func TestLoadSingGeoSiteRejectsOversizedEntryCount(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "geosite.db")

	var content bytes.Buffer
	content.WriteByte(0)
	writeUvarintForTest(t, &content, maxBinaryEntryCount+1)
	if err := os.WriteFile(path, content.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: path}
	err := loadSingGeoSite(&source)
	if err == nil {
		t.Fatal("expected oversized entry count error")
	}
	if !strings.Contains(err.Error(), "singgeo entry count too large") {
		t.Fatalf("error=%q want oversized entry count", err)
	}
}

func TestLoadSingGeoSiteRejectsOversizedString(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "geosite.db")

	var content bytes.Buffer
	content.WriteByte(0)
	writeUvarintForTest(t, &content, 1)
	writeUvarintForTest(t, &content, maxBinaryStringLength+1)
	if err := os.WriteFile(path, content.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	source := LoadedSource{Path: path}
	err := loadSingGeoSite(&source)
	if err == nil {
		t.Fatal("expected oversized string error")
	}
	if !strings.Contains(err.Error(), "string length too large") {
		t.Fatalf("error=%q want oversized string", err)
	}
}

func TestLoadSourceDoesNotKeepPartialSingGeoRulesOnError(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "geosite.db")
	writePartialSingGeoFile(t, path)

	loaded, diagnostics := loadSource(DiscoveredSource{Display: "geosite.db", Path: path})
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics=%d want=1", len(diagnostics))
	}
	if len(loaded.DomainRule) != 0 {
		t.Fatalf("domain rules=%d want=0 after failed load", len(loaded.DomainRule))
	}
	if loaded.Format != "" {
		t.Fatalf("format=%q want empty after failed load", loaded.Format)
	}
}

func TestDBCompatibilityDoesNotKeepPartialFailedAttempt(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "ambiguous.db")
	writePartialSingGeoFile(t, path)

	loaded, diagnostics := loadSource(DiscoveredSource{Display: "ambiguous.db", Path: path})
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics=%d want=1", len(diagnostics))
	}
	if len(loaded.DomainRule) != 0 || len(loaded.GeoIPRules) != 0 || loaded.MMDB != nil {
		t.Fatalf("loaded partial data after failed .db compatibility parse: domain=%d geoip=%d mmdb=%t", len(loaded.DomainRule), len(loaded.GeoIPRules), loaded.MMDB != nil)
	}
}

func writePartialSingGeoFile(t *testing.T, path string) {
	t.Helper()

	var payload bytes.Buffer
	payload.WriteByte(1)
	writeVStringForTest(t, &payload, "google.com")
	payload.WriteByte(1)
	writeUvarintForTest(t, &payload, 20)

	var metadata bytes.Buffer
	metadata.WriteByte(0)
	writeUvarintForTest(t, &metadata, 1)
	writeVStringForTest(t, &metadata, "google")
	writeUvarintForTest(t, &metadata, 0)
	writeUvarintForTest(t, &metadata, 2)

	content := append(metadata.Bytes(), payload.Bytes()...)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeUvarintForTest(t *testing.T, buf *bytes.Buffer, v uint64) {
	t.Helper()
	var tmp [10]byte
	n := binary.PutUvarint(tmp[:], v)
	if _, err := buf.Write(tmp[:n]); err != nil {
		t.Fatal(err)
	}
}

func writeVStringForTest(t *testing.T, buf *bytes.Buffer, s string) {
	t.Helper()
	writeUvarintForTest(t, buf, uint64(len(s)))
	if _, err := buf.WriteString(s); err != nil {
		t.Fatal(err)
	}
}
