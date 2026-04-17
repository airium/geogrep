package geogrep

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed webui/*
var embeddedWebUI embed.FS

type webRuntime struct {
	cfg         CLIConfig
	discovery   DiscoveryResult
	databases   []LoadedDatabase
	diagnostics []Diagnostic

	lookupMu sync.Mutex
	webUIFS  fs.FS
}

type apiFindRequest struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type apiFindResponse struct {
	Request apiFindRequest `json:"request"`
	Result  ExportDocument `json:"result"`
}

type apiErrorResponse struct {
	Error string `json:"error"`
}

type healthResponse struct {
	Status       string `json:"status"`
	Service      string `json:"service"`
	Version      string `json:"version"`
	DatabaseRoot string `json:"database_root"`
	DatabaseCnt  int    `json:"database_count"`
}

func runWeb(cfg CLIConfig) int {
	discovery, err := resolveDiscovery(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery error: %v\n", err)
		return 1
	}

	databases, diagnostics := loadDatabases(discovery)
	defer closeDatabases(databases)

	runtime := &webRuntime{
		cfg:         cfg,
		discovery:   discovery,
		databases:   databases,
		diagnostics: diagnostics,
	}

	if len(diagnostics) > 0 {
		printDiagnostics(diagnostics)
	}

	if !cfg.APIOnly {
		webUIFS, err := resolveWebUIFS(cfg.WebUIPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "webui error: %v\n", err)
			return 1
		}
		runtime.webUIFS = webUIFS
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", runtime.handleHealth)
	mux.HandleFunc("/openapi.json", runtime.handleOpenAPI)
	mux.HandleFunc("/api/find/auto", runtime.handleMissingFindValue)
	mux.HandleFunc("/api/find/auto/", runtime.makeAPIFindHandler("auto", ForceAuto, "/api/find/auto/"))
	mux.HandleFunc("/api/find/ipv4", runtime.handleMissingFindValue)
	mux.HandleFunc("/api/find/ipv4/", runtime.makeAPIFindHandler("ipv4", ForceIPv4, "/api/find/ipv4/"))
	mux.HandleFunc("/api/find/ipv6", runtime.handleMissingFindValue)
	mux.HandleFunc("/api/find/ipv6/", runtime.makeAPIFindHandler("ipv6", ForceIPv6, "/api/find/ipv6/"))
	mux.HandleFunc("/api/find/domain", runtime.handleMissingFindValue)
	mux.HandleFunc("/api/find/domain/", runtime.makeAPIFindHandler("domain", ForceDomain, "/api/find/domain/"))
	mux.HandleFunc("/api/find/keyword", runtime.handleMissingFindValue)
	mux.HandleFunc("/api/find/keyword/", runtime.makeAPIFindHandler("keyword", ForceKeyword, "/api/find/keyword/"))

	if cfg.APIOnly {
		mux.HandleFunc("/", runtime.handleAPIOnlyRoot)
	} else {
		mux.HandleFunc("/find/", runtime.handleShareRedirect)
		mux.HandleFunc("/", runtime.handleWebUI)
	}

	fmt.Printf("[geogrep] web listening on http://%s (api_only=%t, databases=%d)\n", cfg.ListenAddr, cfg.APIOnly, len(discovery.Databases))
	err = http.ListenAndServe(cfg.ListenAddr, mux)
	if err != nil {
		fmt.Fprintf(os.Stderr, "web server error: %v\n", err)
		return 1
	}

	return 0
}

func (s *webRuntime) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeAPIJSON(w, http.StatusOK, healthResponse{
		Status:       "ok",
		Service:      "geogrep",
		Version:      Version,
		DatabaseRoot: s.discovery.RootDir,
		DatabaseCnt:  len(s.discovery.Databases),
	})
}

func (s *webRuntime) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeAPIJSON(w, http.StatusOK, s.buildOpenAPISpec(r))
}

func (s *webRuntime) buildOpenAPISpec(r *http.Request) map[string]any {
	servers := []map[string]string{}
	if r != nil && r.Host != "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		servers = append(servers, map[string]string{"url": scheme + "://" + r.Host})
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "geogrep Web API",
			"version":     Version,
			"description": "HTTP API for geodata lookups via geogrep.",
		},
		"servers": servers,
		"paths": map[string]any{
			"/health": map[string]any{
				"get": map[string]any{
					"summary": "Health check",
					"responses": map[string]any{
						"200": map[string]any{"description": "Service is healthy"},
					},
				},
			},
			"/api/find/auto/{value}": map[string]any{
				"get": makeFindOperation("Auto detect and lookup", "auto"),
			},
			"/api/find/ipv4/{value}": map[string]any{
				"get": makeFindOperation("Lookup as IPv4 or CIDR", "ipv4"),
			},
			"/api/find/ipv6/{value}": map[string]any{
				"get": makeFindOperation("Lookup as IPv6 or CIDR", "ipv6"),
			},
			"/api/find/domain/{value}": map[string]any{
				"get": makeFindOperation("Lookup as domain", "domain"),
			},
			"/api/find/keyword/{value}": map[string]any{
				"get": makeFindOperation("Lookup as keyword", "keyword"),
			},
			"/openapi.json": map[string]any{
				"get": map[string]any{
					"summary": "OpenAPI document",
					"responses": map[string]any{
						"200": map[string]any{"description": "OpenAPI JSON"},
					},
				},
			},
		},
	}
}

func makeFindOperation(summary string, example string) map[string]any {
	return map[string]any{
		"summary": summary,
		"parameters": []map[string]any{
			{
				"name":        "value",
				"in":          "path",
				"required":    true,
				"description": "Lookup value",
				"schema": map[string]any{
					"type": "string",
				},
				"example": example,
			},
		},
		"responses": map[string]any{
			"200": map[string]any{"description": "Lookup result"},
			"400": map[string]any{"description": "Bad request"},
			"405": map[string]any{"description": "Method not allowed"},
		},
	}
}

func resolveWebUIFS(customPath string) (fs.FS, error) {
	if customPath != "" {
		resolved, err := filepath.Abs(customPath)
		if err != nil {
			return nil, fmt.Errorf("resolve --webui path: %w", err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, fmt.Errorf("stat --webui path: %w", err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("--webui path must be a directory: %s", resolved)
		}
		return os.DirFS(resolved), nil
	}
	return fs.Sub(embeddedWebUI, "webui")
}

func (s *webRuntime) handleMissingFindValue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeAPIError(w, http.StatusBadRequest, "missing find value in path")
}

func (s *webRuntime) makeAPIFindHandler(kind string, force ForceKind, prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		escapedPath := r.URL.EscapedPath()
		escapedValue := strings.TrimPrefix(escapedPath, prefix)
		if escapedValue == "" {
			writeAPIError(w, http.StatusBadRequest, "missing find value in path")
			return
		}

		value, err := url.PathUnescape(escapedValue)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid encoded path value")
			return
		}
		value = strings.TrimSpace(value)
		if value == "" {
			writeAPIError(w, http.StatusBadRequest, "empty find value")
			return
		}

		query, err := classifyInput(0, RawInput{Value: value, Force: force})
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}

		s.lookupMu.Lock()
		results := runLookups([]Query{query}, s.databases, s.cfg.ReportEmpty)
		s.lookupMu.Unlock()

		document := buildExportDocument(s.discovery, []Query{query}, results, s.diagnostics, s.cfg.ReportEmpty)
		response := apiFindResponse{
			Request: apiFindRequest{Type: kind, Value: value},
			Result:  document,
		}
		writeAPIJSON(w, http.StatusOK, response)
	}
}

func (s *webRuntime) handleAPIOnlyRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.URL.Path != "/" {
		writeAPIError(w, http.StatusNotFound, "not found")
		return
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{
		"service": "geogrep",
		"mode":    "api-only",
		"endpoints": []string{
			"GET /health",
			"GET /openapi.json",
			"GET /api/find/auto/<any>",
			"GET /api/find/ipv4/<IP_or_CIDR>",
			"GET /api/find/ipv6/<IP_or_CIDR>",
			"GET /api/find/domain/<domain>",
			"GET /api/find/keyword/<keyword>",
		},
	})
}

func (s *webRuntime) handleShareRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	escapedPath := strings.TrimPrefix(r.URL.EscapedPath(), "/find/")
	parts := strings.SplitN(escapedPath, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	kind := parts[0]
	if !isShareFindType(kind) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	value, err := url.PathUnescape(parts[1])
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	value = strings.TrimSpace(value)
	if value == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	target := "/?type=" + url.QueryEscape(kind) + "&q=" + url.QueryEscape(value)
	http.Redirect(w, r, target, http.StatusFound)
}

func isShareFindType(kind string) bool {
	switch kind {
	case "auto", "ipv4", "ipv6", "domain", "keyword":
		return true
	default:
		return false
	}
}

func (s *webRuntime) handleWebUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "." || name == "" {
		s.writeIndexHTML(w)
		return
	}

	file, err := s.webUIFS.Open(name)
	if err == nil {
		defer file.Close()
		if stat, statErr := file.Stat(); statErr == nil && !stat.IsDir() {
			http.FileServer(http.FS(s.webUIFS)).ServeHTTP(w, r)
			return
		}
	}

	// Keep visitors pinned to index page for SPA-like behavior.
	s.writeIndexHTML(w)
}

func (s *webRuntime) writeIndexHTML(w http.ResponseWriter) {
	content, err := fs.ReadFile(s.webUIFS, "index.html")
	if err != nil {
		http.Error(w, "index not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeAPIJSON(w, status, apiErrorResponse{Error: message})
}

func writeAPIJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}
