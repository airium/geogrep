package geogrep

import "testing"

func TestParseCLIArgsVersionOnly(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"--version"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if !cfg.ShowVersion {
		t.Fatal("expected ShowVersion to be true")
	}
	if len(cfg.Inputs) != 0 {
		t.Fatalf("expected no inputs, got %d", len(cfg.Inputs))
	}
}

func TestParseCLIArgsShortVersionOnly(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"-v"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if !cfg.ShowVersion {
		t.Fatal("expected ShowVersion to be true")
	}
}
