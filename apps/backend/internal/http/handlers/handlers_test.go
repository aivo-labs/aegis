package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aivo-labs/aegis/backend/internal/service"
)

func TestHealthHandler(t *testing.T) {
	protSvc := service.NewProtectionService(nil, "localhost:8080", "localhost:8081", true, 1048576)
	h := NewHealthHandler(protSvc, "8080")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.Health(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}
	if body["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", body["status"])
	}
	if body["service"] != "aegis-backend-go" {
		t.Errorf("expected service 'aegis-backend-go', got %v", body["service"])
	}
}

func TestCveHandler(t *testing.T) {
	cveSvc := service.NewCveService()
	h := NewCveHandler(cveSvc)

	// 1. Default (French)
	reqFR := httptest.NewRequest(http.MethodGet, "/api/cve/feed", nil)
	wFR := httptest.NewRecorder()
	h.Feed(wFR, reqFR)

	respFR := wFR.Result()
	if respFR.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", respFR.StatusCode)
	}

	var bodyFR map[string]interface{}
	if err := json.NewDecoder(respFR.Body).Decode(&bodyFR); err != nil {
		t.Fatalf("failed to decode feed items: %v", err)
	}
	cvesFR, ok := bodyFR["cves"].([]interface{})
	if !ok || len(cvesFR) == 0 {
		t.Errorf("expected CVE items in feed, got %v", bodyFR["cves"])
	}
	if bodyFR["lang"] != "fr" {
		t.Errorf("expected lang 'fr', got %v", bodyFR["lang"])
	}

	// 2. Explicit English (?lang=en)
	reqEN := httptest.NewRequest(http.MethodGet, "/api/cve/feed?lang=en", nil)
	wEN := httptest.NewRecorder()
	h.Feed(wEN, reqEN)

	respEN := wEN.Result()
	if respEN.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", respEN.StatusCode)
	}

	var bodyEN map[string]interface{}
	if err := json.NewDecoder(respEN.Body).Decode(&bodyEN); err != nil {
		t.Fatalf("failed to decode feed items: %v", err)
	}
	if bodyEN["lang"] != "en" {
		t.Errorf("expected lang 'en', got %v", bodyEN["lang"])
	}
}

func TestProtectionHandler_StatusAndToggle(t *testing.T) {
	protSvc := service.NewProtectionService(nil, "localhost:8080", "localhost:8081", true, 1048576)
	h := NewProtectionHandler(protSvc)

	// Status initially active
	req := httptest.NewRequest(http.MethodGet, "/api/protection/status", nil)
	w := httptest.NewRecorder()
	h.Protection(w, req)

	var st map[string]interface{}
	json.NewDecoder(w.Result().Body).Decode(&st)
	if st["protection_enabled"] != true {
		t.Errorf("expected protection_enabled=true, got %v", st["protection_enabled"])
	}

	// Disable protection
	body := strings.NewReader(`{"protection_enabled": false}`)
	reqDis := httptest.NewRequest(http.MethodPost, "/api/protection/toggle", body)
	wDis := httptest.NewRecorder()
	h.Protection(wDis, reqDis)

	var stDis map[string]interface{}
	json.NewDecoder(wDis.Result().Body).Decode(&stDis)
	if stDis["protection_enabled"] != false {
		t.Errorf("expected protection_enabled=false after toggle, got %v", stDis["protection_enabled"])
	}

	// Re-enable protection
	bodyEn := strings.NewReader(`{"protection_enabled": true}`)
	reqEn := httptest.NewRequest(http.MethodPost, "/api/protection/toggle", bodyEn)
	wEn := httptest.NewRecorder()
	h.Protection(wEn, reqEn)

	var stEn map[string]interface{}
	json.NewDecoder(wEn.Result().Body).Decode(&stEn)
	if stEn["protection_enabled"] != true {
		t.Errorf("expected protection_enabled=true after toggle, got %v", stEn["protection_enabled"])
	}
}
