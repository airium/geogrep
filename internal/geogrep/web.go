package geogrep

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed webui/*
var embeddedWebUI embed.FS

const (
	maxLookupValueLength = 2048
)

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

type apiListRequest struct {
	Ruleset string `json:"ruleset"`
}

type apiListResponse struct {
	Request apiListRequest `json:"request"`
	Result  ListDocument   `json:"result"`
}

type apiErrorResponse struct {
	Error string `json:"error"`
}

type healthResponse struct {
	Status      string `json:"status"`
	Service     string `json:"service"`
	Version     string `json:"version"`
	DatabaseCnt int    `json:"database_count"`
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
	mux.HandleFunc("/api/list", runtime.handleMissingListRuleset)
	mux.HandleFunc("/api/list/", runtime.handleAPIList)

	if cfg.APIOnly {
		mux.HandleFunc("/", runtime.handleAPIOnlyRoot)
	} else {
		mux.HandleFunc("/find/", runtime.handleShareRedirect)
		mux.HandleFunc("/", runtime.handleWebUI)
	}

	fmt.Printf("[geogrep] web listening on http://%s (api_only=%t, databases=%d)\n", cfg.ListenAddr, cfg.APIOnly, len(discovery.Databases))
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           wrapWithPathGuards(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	err = server.ListenAndServe()
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
		Status:      "ok",
		Service:     "geogrep",
		Version:     Version,
		DatabaseCnt: len(s.discovery.Databases),
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
			"/api/list/{ruleset}": map[string]any{
				"get": makeListOperation(),
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

func makeListOperation() map[string]any {
	return map[string]any{
		"summary": "List rules from a ruleset",
		"parameters": []map[string]any{
			{
				"name":        "ruleset",
				"in":          "path",
				"required":    true,
				"description": "Ruleset or category name",
				"schema": map[string]any{
					"type": "string",
				},
				"example": "cn",
			},
		},
		"responses": map[string]any{
			"200": map[string]any{"description": "Ruleset listing"},
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

func (s *webRuntime) handleMissingListRuleset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeAPIError(w, http.StatusBadRequest, "missing ruleset in path")
}

func (s *webRuntime) handleAPIList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	escapedPath := r.URL.EscapedPath()
	escapedRuleset := strings.TrimPrefix(escapedPath, "/api/list/")
	if escapedRuleset == "" {
		writeAPIError(w, http.StatusBadRequest, "missing ruleset in path")
		return
	}

	ruleset, err := url.PathUnescape(escapedRuleset)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid encoded path value")
		return
	}
	ruleset = strings.TrimSpace(ruleset)
	if ruleset == "" {
		writeAPIError(w, http.StatusBadRequest, "empty ruleset")
		return
	}
	if len(ruleset) > maxLookupValueLength {
		writeAPIError(w, http.StatusRequestURITooLong, "ruleset too long")
		return
	}

	s.lookupMu.Lock()
	results := listRulesets(s.databases, []string{ruleset})
	s.lookupMu.Unlock()

	// Avoid leaking loader/runtime internals in public API responses.
	document := buildListDocument(s.discovery, results, nil)
	response := apiListResponse{
		Request: apiListRequest{Ruleset: ruleset},
		Result:  document,
	}
	writeAPIJSON(w, http.StatusOK, response)
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
		if len(value) > maxLookupValueLength {
			writeAPIError(w, http.StatusRequestURITooLong, "find value too long")
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

		// Avoid leaking loader/runtime internals in public API responses.
		document := buildExportDocument(s.discovery, []Query{query}, results, nil, s.cfg.ReportEmpty)
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
			"GET /api/list/<ruleset>",
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
	if kind == "list" {
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
		target := "/?mode=list&q=" + url.QueryEscape(value)
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
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

	target := "/?mode=find&type=" + url.QueryEscape(kind) + "&q=" + url.QueryEscape(value)
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

	name, isIndex, ok := sanitizeWebAssetPath(r.URL.EscapedPath())
	if !ok {
		http.NotFound(w, r)
		return
	}
	if isIndex {
		s.writeIndexHTML(w)
		return
	}

	if s.serveWebAsset(w, name) {
		return
	}

	// Keep visitors pinned to index page for SPA-like behavior.
	s.writeIndexHTML(w)
}

func sanitizeWebAssetPath(escapedPath string) (string, bool, bool) {
	if escapedPath == "" || escapedPath == "/" {
		return "index.html", true, true
	}
	if !strings.HasPrefix(escapedPath, "/") {
		return "", false, false
	}

	raw := strings.TrimPrefix(escapedPath, "/")
	if raw == "" {
		return "index.html", true, true
	}

	lowerRaw := strings.ToLower(raw)
	if strings.Contains(lowerRaw, "%2f") || strings.Contains(lowerRaw, "%5c") {
		return "", false, false
	}

	unescaped, err := url.PathUnescape(raw)
	if err != nil {
		return "", false, false
	}
	if strings.ContainsRune(unescaped, 0) {
		return "", false, false
	}
	unescaped = strings.ReplaceAll(unescaped, "\\", "/")

	parts := strings.Split(unescaped, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", false, false
		}
	}

	cleaned := path.Clean(unescaped)
	if cleaned == "." || cleaned == "" {
		return "index.html", true, true
	}

	return cleaned, false, true
}

func (s *webRuntime) serveWebAsset(w http.ResponseWriter, name string) bool {
	content, err := fs.ReadFile(s.webUIFS, name)
	if err != nil {
		return false
	}

	setSecurityHeaders(w)
	contentType := mime.TypeByExtension(strings.ToLower(path.Ext(name)))
	if contentType == "" {
		contentType = http.DetectContentType(content)
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
	return true
}

func wrapWithPathGuards(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasSuspiciousTraversalPath(r.URL.EscapedPath()) {
			setSecurityHeaders(w)
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hasSuspiciousTraversalPath(escapedPath string) bool {
	lower := strings.ToLower(escapedPath)
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "\\") || strings.Contains(lower, "%5c") {
		return true
	}
	if strings.Contains(lower, "%2e%2e") {
		return true
	}
	if strings.HasPrefix(lower, "/..") || strings.Contains(lower, "/../") || strings.HasSuffix(lower, "/..") {
		return true
	}
	return false
}

func (s *webRuntime) writeIndexHTML(w http.ResponseWriter) {
	content, err := fs.ReadFile(s.webUIFS, "index.html")
	if err != nil {
		http.Error(w, "index not found", http.StatusInternalServerError)
		return
	}
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeAPIJSON(w, status, apiErrorResponse{Error: message})
}

func writeAPIJSON(w http.ResponseWriter, status int, payload any) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
}
