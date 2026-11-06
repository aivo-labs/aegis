package service

import (
	"testing"
)

func TestClassifyIngressEvent(t *testing.T) {
	cases := []struct {
		uri        string
		method     string
		decision   string
		threatType string
		status     int
		wantCat    string
		wantProb   int
	}{
		{"/wp-login.php", "POST", "BLOCK", "CMS_PHP_BOT_PROBE", 403, "SONDE BOTNET CMS / PHP", 96},
		{"/.env", "GET", "BLOCK", "SENSITIVE_FILE_PROBE", 403, "SONDE FICHIER SENSIBLE", 95},
		{"/api/v1/users", "GET", "BLOCK", "PENTEST_SCANNER_DETECTED", 403, "SCANNER DE VULNÉRABILITÉS", 94},
		{"/upload", "POST", "BLOCK", "OVERFLOW_PAYLOAD_413", 413, "EXPLOIT BUFFER OVERFLOW (413)", 99},
		{"/api/v1/status", "GET", "ALLOW", "CLEAN_TRAFFIC", 200, "TRAFIC APPLICATIF LÉGITIME", 2},
	}

	for _, c := range cases {
		cat, prob := ClassifyIngressEvent(c.uri, c.method, c.decision, c.threatType, c.status)
		if cat != c.wantCat {
			t.Errorf("ClassifyIngressEvent(%s) category = %v, want %v", c.uri, cat, c.wantCat)
		}
		if prob != c.wantProb {
			t.Errorf("ClassifyIngressEvent(%s) prob = %v, want %v", c.uri, prob, c.wantProb)
		}
	}
}

func TestIPToGeoCoordinates(t *testing.T) {
	lat, lon := IPToGeoCoordinates("127.0.0.1")
	if lat != 48.8566 || lon != 2.3522 {
		t.Errorf("Expected Paris coordinates for localhost, got (%f, %f)", lat, lon)
	}

	lat2, lon2 := IPToGeoCoordinates("185.220.101.42")
	if lat2 == 0 && lon2 == 0 {
		t.Errorf("Expected valid geo coordinates for external IP")
	}
}

func TestGetEnergyTelemetry_RangesAndMetrics(t *testing.T) {
	svc := NewDashboardService(nil, nil, "00000000-0000-0000-0000-000000000001")

	// 1. Default 24h
	res24h, err := svc.GetEnergyTelemetry("24h", "", "", "", "", "all", "all")
	if err != nil {
		t.Fatalf("GetEnergyTelemetry(24h) error = %v", err)
	}
	summary, ok := res24h["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary map")
	}
	if summary["instant_watts"].(float64) <= 0 {
		t.Errorf("expected positive instant_watts")
	}
	if summary["water_usage_liters"].(float64) <= 0 {
		t.Errorf("expected positive water_usage_liters")
	}
	if summary["total_carbon_gco2"].(float64) <= 0 {
		t.Errorf("expected positive total_carbon_gco2")
	}

	// 2. September Month Navigation
	resSept, err := svc.GetEnergyTelemetry("month", "", "", "2026-09", "", "all", "dokploy")
	if err != nil {
		t.Fatalf("GetEnergyTelemetry(month=2026-09) error = %v", err)
	}
	if resSept["range"] != "month" {
		t.Errorf("expected range 'month', got %v", resSept["range"])
	}
	workloads, _ := resSept["workloads"].([]map[string]any)
	for _, wl := range workloads {
		if wl["namespace"] != "dokploy" {
			t.Errorf("expected only dokploy namespace, got %v", wl["namespace"])
		}
	}

	// 3. Year 2026 Navigation
	resYear, err := svc.GetEnergyTelemetry("year", "", "", "", "2026", "all", "all")
	if err != nil {
		t.Fatalf("GetEnergyTelemetry(year=2026) error = %v", err)
	}
	if resYear["range"] != "year" {
		t.Errorf("expected range 'year', got %v", resYear["range"])
	}
	timeseries, ok := resYear["timeseries"].([]EnergyTimePoint)
	if !ok || len(timeseries) == 0 {
		t.Errorf("expected non-empty EnergyTimePoint timeseries for year 2026")
	}
}

