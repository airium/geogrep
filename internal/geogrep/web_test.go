package geogrep

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if location != "/?type=auto&q=google.com" {
		t.Fatalf("location=%s want=/?type=auto&q=google.com", location)
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
	if location != "/?type=ipv4&q=1.1.1.0%2F24" {
		t.Fatalf("location=%s want=/?type=ipv4&q=1.1.1.0%%2F24", location)
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

func TestAPIFindDomainHandler(t *testing.T) {
	runtime := &webRuntime{
		cfg:       CLIConfig{ReportEmpty: true},
		discovery: DiscoveryResult{},
		databases: nil,
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
}
