package geogrep

import "testing"

func TestParseCLIArgsVersionSubcommand(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"version"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "version" {
		t.Fatalf("command=%s want=version", cfg.Command)
	}
	if cfg.Verbose != 0 {
		t.Fatalf("verbose=%d want=0", cfg.Verbose)
	}
}

func TestParseCLIArgsFindVerbose(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"find", "-v", "google.com"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "find" {
		t.Fatalf("command=%s want=find", cfg.Command)
	}
	if cfg.Verbose != 1 {
		t.Fatalf("verbose=%d want=1", cfg.Verbose)
	}
	if !cfg.ReportEmpty {
		t.Fatal("expected ReportEmpty=true when verbose >= 1")
	}
}

func TestParseCLIArgsFindCompactVerbose(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"find", "-vv", "google.com"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Verbose != 2 {
		t.Fatalf("verbose=%d want=2", cfg.Verbose)
	}
}

func TestParseCLIArgsFindVerboseLevel(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"find", "--verbose=3", "google.com"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Verbose != 3 {
		t.Fatalf("verbose=%d want=3", cfg.Verbose)
	}
}

func TestParseCLIArgsWebDefaults(t *testing.T) {
	cfg, err := parseCLIArgs([]string{"web"})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.Command != "web" {
		t.Fatalf("command=%s want=web", cfg.Command)
	}
	if cfg.ListenAddr != "0.0.0.0:8080" {
		t.Fatalf("listen=%s want=0.0.0.0:8080", cfg.ListenAddr)
	}
	if cfg.ReportEmpty {
		t.Fatal("ReportEmpty should be false by default")
	}
}

func TestParseCLIArgsWebFlags(t *testing.T) {
	cfg, err := parseCLIArgs([]string{
		"web",
		"-db", "/tmp/db",
		"--listen", "127.0.0.1:9000",
		"--webui", "./ui",
		"--api-only",
		"-vv",
	})
	if err != nil {
		t.Fatalf("parseCLIArgs returned error: %v", err)
	}
	if cfg.DBDir != "/tmp/db" {
		t.Fatalf("db=%s want=/tmp/db", cfg.DBDir)
	}
	if cfg.ListenAddr != "127.0.0.1:9000" {
		t.Fatalf("listen=%s want=127.0.0.1:9000", cfg.ListenAddr)
	}
	if cfg.WebUIPath != "./ui" {
		t.Fatalf("webui=%s want=./ui", cfg.WebUIPath)
	}
	if !cfg.APIOnly {
		t.Fatal("expected APIOnly=true")
	}
	if cfg.Verbose != 2 {
		t.Fatalf("verbose=%d want=2", cfg.Verbose)
	}
	if !cfg.ReportEmpty {
		t.Fatal("expected ReportEmpty=true when verbose >= 1")
	}
}

func TestParseCLIArgsWebInvalidListen(t *testing.T) {
	_, err := parseCLIArgs([]string{"web", "--listen", "127.0.0.1"})
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

func TestParseCLIArgsMissingSubcommand(t *testing.T) {
	_, err := parseCLIArgs([]string{})
	if err == nil {
		t.Fatal("expected error for missing subcommand")
	}
}

func TestParseCLIArgsUnknownSubcommand(t *testing.T) {
	_, err := parseCLIArgs([]string{"noop"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}
