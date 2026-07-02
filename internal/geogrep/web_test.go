package geogrep

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestHandleShareRedirectAuto(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/find/auto/google.com", nil)
	rr := httptest.NewRecorder()

	runtime.handleShareRedirect(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusFound)
	}
	location := rr.Header().Get("Location")
	if location != "/?mode=find-rule&type=auto&q=google.com" {
		t.Fatalf("location=%s want=/?mode=find-rule&type=auto&q=google.com", location)
	}
}

func TestHandleShareRedirectCIDR(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/find/ipv4/1.1.1.0/24", nil)
	rr := httptest.NewRecorder()

	runtime.handleShareRedirect(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusFound)
	}
	location := rr.Header().Get("Location")
	if location != "/?mode=find-rule&type=ipv4&q=1.1.1.0%2F24" {
		t.Fatalf("location=%s want=/?mode=find-rule&type=ipv4&q=1.1.1.0%%2F24", location)
	}
}

func TestHandleShareRedirectInvalidType(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/find/unknown/google.com", nil)
	rr := httptest.NewRecorder()

	runtime.handleShareRedirect(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusFound)
	}
	location := rr.Header().Get("Location")
	if location != "/" {
		t.Fatalf("location=%s want=/", location)
	}
}

func TestHandleShareRedirectListRule(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/find/list-rule/cn", nil)
	rr := httptest.NewRecorder()

	runtime.handleShareRedirect(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusFound)
	}
	location := rr.Header().Get("Location")
	if location != "/?mode=list-rule&q=cn" {
		t.Fatalf("location=%s want=/?mode=list-rule&q=cn", location)
	}
}

func TestHandleShareRedirectLegacyList(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/find/list/cn", nil)
	rr := httptest.NewRecorder()

	runtime.handleShareRedirect(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusFound)
	}
	location := rr.Header().Get("Location")
	if location != "/?mode=list-rule&q=cn" {
		t.Fatalf("location=%s want=/?mode=list-rule&q=cn", location)
	}
}

func TestHandleShareRedirectListRuleIncludeMMDB(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/find/list-rule/cn?include_mmdb=true", nil)
	rr := httptest.NewRecorder()

	runtime.handleShareRedirect(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusFound)
	}
	location := rr.Header().Get("Location")
	if location != "/?mode=list-rule&q=cn&include_mmdb=true" {
		t.Fatalf("location=%s want=/?mode=list-rule&q=cn&include_mmdb=true", location)
	}
}

func TestHandleShareRedirectFindCategory(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/find/find-category/%5Ecn%24?include_mmdb=true", nil)
	rr := httptest.NewRecorder()

	runtime.handleShareRedirect(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusFound)
	}
	location := rr.Header().Get("Location")
	if location != "/?mode=find-category&q=%5Ecn%24&include_mmdb=true" {
		t.Fatalf("location=%s want=/?mode=find-category&q=%%5Ecn%%24&include_mmdb=true", location)
	}
}

func TestHandleShareRedirectLegacyListCategory(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/find/list-category/%5Ecn%24?include_mmdb=true", nil)
	rr := httptest.NewRecorder()

	runtime.handleShareRedirect(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusFound)
	}
	location := rr.Header().Get("Location")
	if location != "/?mode=find-category&q=%5Ecn%24&include_mmdb=true" {
		t.Fatalf("location=%s want=/?mode=find-category&q=%%5Ecn%%24&include_mmdb=true", location)
	}
}

func TestAPIFindDomainHandler(t *testing.T) {
	runtime := &webRuntime{
		cfg:       CLIConfig{ReportEmpty: true},
		discovery: DiscoveryResult{},
		databases: nil,
		diagnostics: []Diagnostic{{
			Level:   "warning",
			Scope:   "foo",
			Message: "bar",
		}},
	}
	h := runtime.makeAPIFindHandler("domain", ForceDomain, "/api/find/domain/")

	req := httptest.NewRequest(http.MethodGet, "/api/find/domain/google.com", nil)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var payload apiFindResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Request.Type != "domain" {
		t.Fatalf("request.type=%s want=domain", payload.Request.Type)
	}
	if payload.Request.Value != "google.com" {
		t.Fatalf("request.value=%s want=google.com", payload.Request.Value)
	}
	if payload.Result.Metadata.QueryCount != 1 {
		t.Fatalf("query_count=%d want=1", payload.Result.Metadata.QueryCount)
	}
	if len(payload.Result.Results) != 1 {
		t.Fatalf("results=%d want=1", len(payload.Result.Results))
	}
	if payload.Result.Results[0].Query.Kind != QueryDomain {
		t.Fatalf("kind=%s want=%s", payload.Result.Results[0].Query.Kind, QueryDomain)
	}
	if len(payload.Result.Diagnostics) != 0 {
		t.Fatalf("diagnostics=%d want=0", len(payload.Result.Diagnostics))
	}
}

func TestAPIListHandler(t *testing.T) {
	runtime := &webRuntime{
		discovery: DiscoveryResult{Databases: []DiscoveredDatabase{{Name: "geoip.dat"}}},
		databases: []LoadedDatabase{{
			Name: "geoip.dat",
			Sources: []LoadedSource{{
				Display: "geoip.dat",
				Format:  "dat",
				GeoIPRules: []GeoIPRule{{
					SubEntry: "CN",
					Rule:     "1.0.1.0/24",
				}},
			}},
		}},
		diagnostics: []Diagnostic{{
			Level:   "warning",
			Scope:   "foo",
			Message: "bar",
		}},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/list/cn", nil)
	rr := httptest.NewRecorder()

	runtime.handleAPIList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var payload apiListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Request.Ruleset != "cn" {
		t.Fatalf("request.ruleset=%s want=cn", payload.Request.Ruleset)
	}
	if payload.Request.IncludeMMDB {
		t.Fatal("include_mmdb should default to false")
	}
	if payload.Result.Metadata.RulesetCount != 1 {
		t.Fatalf("ruleset_count=%d want=1", payload.Result.Metadata.RulesetCount)
	}
	if len(payload.Result.Results) != 1 || len(payload.Result.Results[0].Rules) != 1 {
		t.Fatalf("results=%#v want one rule", payload.Result.Results)
	}
	if payload.Result.Results[0].Rules[0].Ruleset != "CN" {
		t.Fatalf("matched ruleset=%s want=CN", payload.Result.Results[0].Rules[0].Ruleset)
	}
	if len(payload.Result.Diagnostics) != 0 {
		t.Fatalf("diagnostics=%d want=0", len(payload.Result.Diagnostics))
	}
}

func TestAPIListHandlerIncludeMMDBQuery(t *testing.T) {
	runtime := &webRuntime{
		discovery: DiscoveryResult{Databases: []DiscoveredDatabase{{Name: "geoip.dat"}}},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/list/cn?include_mmdb=true", nil)
	rr := httptest.NewRecorder()

	runtime.handleAPIList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var payload apiListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !payload.Request.IncludeMMDB {
		t.Fatal("expected include_mmdb=true in response request")
	}
}

func TestAPIListHandlerAutoIncludesMMDBOnlyDatabases(t *testing.T) {
	runtime := &webRuntime{
		discovery: DiscoveryResult{Databases: []DiscoveredDatabase{{Name: "geoip.mmdb"}}},
		databases: []LoadedDatabase{{
			Name: "geoip.mmdb",
			Sources: []LoadedSource{{
				Display: "geoip.mmdb",
				Format:  "mmdb",
				MMDB:    &MMDBSource{},
			}},
		}},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/list/cn", nil)
	rr := httptest.NewRecorder()

	runtime.handleAPIList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var payload apiListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !payload.Request.IncludeMMDB {
		t.Fatal("expected include_mmdb to be auto-enabled for MMDB-only databases")
	}
}

func TestAPIListCategoryHandler(t *testing.T) {
	runtime := &webRuntime{
		discovery: DiscoveryResult{Databases: []DiscoveredDatabase{{Name: "geosite.dat"}}},
		databases: []LoadedDatabase{{
			Name: "geosite.dat",
			Sources: []LoadedSource{{
				Display: "geosite.dat",
				Format:  "dat",
				DomainRule: []DomainRule{{
					SubEntry: "google-cn",
					Rule:     "domain:google.cn",
					Kind:     DomainExact,
					Value:    "google.cn",
				}},
			}},
		}},
		diagnostics: []Diagnostic{{
			Level:   "warning",
			Scope:   "foo",
			Message: "bar",
		}},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/list-category/cn", nil)
	rr := httptest.NewRecorder()

	runtime.handleAPIListCategory(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var payload apiListCategoryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Request.Pattern != "cn" {
		t.Fatalf("request.pattern=%s want=cn", payload.Request.Pattern)
	}
	if payload.Request.IncludeMMDB {
		t.Fatal("include_mmdb should default to false")
	}
	if payload.Result.Metadata.PatternCount != 1 {
		t.Fatalf("pattern_count=%d want=1", payload.Result.Metadata.PatternCount)
	}
	if len(payload.Result.Results) != 1 || len(payload.Result.Results[0].Categories) != 1 {
		t.Fatalf("results=%#v want one category", payload.Result.Results)
	}
	if payload.Result.Results[0].Categories[0].Category != "google-cn" {
		t.Fatalf("category=%s want=google-cn", payload.Result.Results[0].Categories[0].Category)
	}
	if len(payload.Result.Diagnostics) != 0 {
		t.Fatalf("diagnostics=%d want=0", len(payload.Result.Diagnostics))
	}
}

func TestAPIListCategoryHandlerIncludeMMDBQuery(t *testing.T) {
	runtime := &webRuntime{
		discovery: DiscoveryResult{Databases: []DiscoveredDatabase{{Name: "geoip.dat"}}},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/list-category/cn?include_mmdb=true", nil)
	rr := httptest.NewRecorder()

	runtime.handleAPIListCategory(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var payload apiListCategoryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !payload.Request.IncludeMMDB {
		t.Fatal("expected include_mmdb=true in response request")
	}
}

func TestAPIListCategoryHandlerAutoIncludesMMDBOnlyDatabases(t *testing.T) {
	runtime := &webRuntime{
		discovery: DiscoveryResult{Databases: []DiscoveredDatabase{{Name: "geoip.mmdb"}}},
		databases: []LoadedDatabase{{
			Name: "geoip.mmdb",
			Sources: []LoadedSource{{
				Display: "geoip.mmdb",
				Format:  "mmdb",
				MMDB:    &MMDBSource{},
			}},
		}},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/list-category/cn", nil)
	rr := httptest.NewRecorder()

	runtime.handleAPIListCategory(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var payload apiListCategoryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !payload.Request.IncludeMMDB {
		t.Fatal("expected include_mmdb to be auto-enabled for MMDB-only databases")
	}
}

func TestAPIListCategoryHandlerTreatsRegexSyntaxAsText(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/api/list-category/%5B", nil)
	rr := httptest.NewRecorder()

	runtime.handleAPIListCategory(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var payload apiListCategoryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Request.Pattern != "[" {
		t.Fatalf("pattern=%q want [", payload.Request.Pattern)
	}
	if len(payload.Result.Results) != 1 {
		t.Fatalf("results=%d want=1", len(payload.Result.Results))
	}
}

func TestAPIListHandlerMissingRuleset(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/api/list", nil)
	rr := httptest.NewRecorder()

	runtime.handleMissingListRuleset(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusBadRequest)
	}
}

func TestAPIFindHandlerMissingValue(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/api/find/ipv4", nil)
	rr := httptest.NewRecorder()

	runtime.handleMissingFindValue(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusBadRequest)
	}

	var payload apiErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Error == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestHandleHealth(t *testing.T) {
	runtime := &webRuntime{
		discovery: DiscoveryResult{RootDir: "/tmp/db", Databases: []DiscoveredDatabase{{Name: "a"}, {Name: "b"}}},
	}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	runtime.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}

	var payload healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Status != "ok" {
		t.Fatalf("status=%s want=ok", payload.Status)
	}
	if payload.DatabaseCnt != 2 {
		t.Fatalf("database_count=%d want=2", payload.DatabaseCnt)
	}
	if payload.Version != Version {
		t.Fatalf("version=%s want=%s", payload.Version, Version)
	}
}

func TestHandleOpenAPI(t *testing.T) {
	runtime := &webRuntime{}
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()

	runtime.handleOpenAPI(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "\"openapi\": \"3.0.3\"") {
		t.Fatalf("unexpected openapi body: %s", body)
	}
	if !strings.Contains(body, "\"/health\"") {
		t.Fatalf("expected /health path in schema, got: %s", body)
	}
	if !strings.Contains(body, "\"/api/list/{ruleset}\"") {
		t.Fatalf("expected /api/list path in schema, got: %s", body)
	}
	if !strings.Contains(body, "\"/api/list-category/{pattern}\"") {
		t.Fatalf("expected /api/list-category path in schema, got: %s", body)
	}
}

func TestEmbeddedWebUIShowsRuntimeVersion(t *testing.T) {
	content, err := fs.ReadFile(embeddedWebUI, "webui/index.html")
	if err != nil {
		t.Fatalf("read embedded webui: %v", err)
	}
	html := string(content)
	if !strings.Contains(html, "data-version-label") {
		t.Fatal("expected version label placeholder in embedded UI")
	}
	if !strings.Contains(html, `fetch("/health"`) {
		t.Fatal("expected embedded UI to load runtime version from /health")
	}
	if !strings.Contains(html, `"version " + version`) {
		t.Fatal("expected embedded UI to render returned version")
	}
	if !strings.Contains(html, `value="find-category"`) || !strings.Contains(html, `/api/list-category/`) {
		t.Fatal("expected embedded UI to include category discovery mode")
	}
}

func TestSanitizeWebAssetPath(t *testing.T) {
	tests := []struct {
		name      string
		escaped   string
		wantPath  string
		wantIndex bool
		wantOK    bool
	}{
		{name: "index", escaped: "/", wantPath: "index.html", wantIndex: true, wantOK: true},
		{name: "nested asset", escaped: "/assets/app.js", wantPath: "assets/app.js", wantIndex: false, wantOK: true},
		{name: "dotdot", escaped: "/../etc/passwd", wantPath: "", wantIndex: false, wantOK: false},
		{name: "encoded dotdot", escaped: "/%2e%2e/%2e%2e/etc/passwd", wantPath: "", wantIndex: false, wantOK: false},
		{name: "encoded slash", escaped: "/assets%2fapp.js", wantPath: "", wantIndex: false, wantOK: false},
		{name: "encoded backslash", escaped: "/assets%5capp.js", wantPath: "", wantIndex: false, wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotPath, gotIndex, gotOK := sanitizeWebAssetPath(tc.escaped)
			if gotPath != tc.wantPath || gotIndex != tc.wantIndex || gotOK != tc.wantOK {
				t.Fatalf("sanitizeWebAssetPath(%q)=(%q,%t,%t) want=(%q,%t,%t)", tc.escaped, gotPath, gotIndex, gotOK, tc.wantPath, tc.wantIndex, tc.wantOK)
			}
		})
	}
}

func TestHandleWebUITraversalBlocked(t *testing.T) {
	runtime := &webRuntime{webUIFS: fs.FS(fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>ok</html>")},
	})}
	req := httptest.NewRequest(http.MethodGet, "/../etc/passwd", nil)
	rr := httptest.NewRecorder()

	runtime.handleWebUI(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusNotFound)
	}
}

func TestAPIFindHandlerRejectsLongValue(t *testing.T) {
	runtime := &webRuntime{}
	h := runtime.makeAPIFindHandler("keyword", ForceKeyword, "/api/find/keyword/")
	value := strings.Repeat("a", maxLookupValueLength+1)
	req := httptest.NewRequest(http.MethodGet, "/api/find/keyword/"+value, nil)
	rr := httptest.NewRecorder()

	h(rr, req)

	if rr.Code != http.StatusRequestURITooLong {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusRequestURITooLong)
	}
	var payload apiErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Error == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestHasSuspiciousTraversalPath(t *testing.T) {
	tests := []struct {
		path    string
		suspect bool
	}{
		{path: "/", suspect: false},
		{path: "/api/find/domain/google.com", suspect: false},
		{path: "/../etc/passwd", suspect: true},
		{path: "/%2e%2e/%2e%2e/etc/passwd", suspect: true},
		{path: "/foo%5cbar", suspect: true},
		{path: "/foo\\bar", suspect: true},
	}

	for _, tc := range tests {
		if got := hasSuspiciousTraversalPath(tc.path); got != tc.suspect {
			t.Fatalf("hasSuspiciousTraversalPath(%q)=%t want=%t", tc.path, got, tc.suspect)
		}
	}
}

func TestWrapWithPathGuardsBlocksTraversalBeforeMuxRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	guarded := wrapWithPathGuards(mux)
	req := httptest.NewRequest(http.MethodGet, "/../etc/passwd", nil)
	rr := httptest.NewRecorder()

	guarded.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusNotFound)
	}
	if location := rr.Header().Get("Location"); location != "" {
		t.Fatalf("unexpected redirect location=%s", location)
	}
}
