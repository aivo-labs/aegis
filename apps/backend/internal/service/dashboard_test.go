package service

import (
	"strings"
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
	if summary["avg_cpu_load_pct"].(float64) <= 0 {
		t.Errorf("expected positive avg_cpu_load_pct, got %v", summary["avg_cpu_load_pct"])
	}

	nodes, _ := res24h["nodes"].([]map[string]any)
	if len(nodes) == 0 || nodes[0]["provider"] != "OVHcloud / KVM VPS" {
		t.Errorf("expected OVHcloud provider, got %v", nodes)
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

	// Verify all user workloads are included in full list
	resAll, _ := svc.GetEnergyTelemetry("24h", "", "", "", "", "all", "all")
	allWl, _ := resAll["workloads"].([]map[string]any)
	expectedDomains := []string{"aivo.fr", "flow.aivo.fr", "nicolas.baud.dev", "aegis.aivo.fr"}
	for _, domain := range expectedDomains {
		found := false
		for _, wl := range allWl {
			srv := wl["service"].(string)
			if strings.Contains(srv, domain) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected workload containing %s, but not found in %v", domain, allWl)
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
	for _, pt := range timeseries {
		if pt.CpuLoadPct <= 0 {
			t.Errorf("expected positive CpuLoadPct in timeseries point %v", pt)
		}
	}
}

func TestGetEnergyTelemetry_DeterminismAndExport(t *testing.T) {
	svc := NewDashboardService(nil, nil, "00000000-0000-0000-0000-000000000001")

	// 1. Déterminisme absolu de Juillet 2026 : deux appels successifs doivent renvoyer exactement les mêmes valeurs
	call1, err := svc.GetEnergyTelemetry("month", "", "", "2026-07", "", "all", "all")
	if err != nil {
		t.Fatalf("call1 error: %v", err)
	}
	call2, err := svc.GetEnergyTelemetry("month", "", "", "2026-07", "", "all", "all")
	if err != nil {
		t.Fatalf("call2 error: %v", err)
	}

	sum1 := call1["summary"].(map[string]any)
	sum2 := call2["summary"].(map[string]any)

	if sum1["avg_watts"] != sum2["avg_watts"] || sum1["avg_watts"].(float64) != 13.20 {
		t.Errorf("expected avg_watts = 13.20, got call1=%v, call2=%v", sum1["avg_watts"], sum2["avg_watts"])
	}
	if sum1["total_carbon_gco2"] != sum2["total_carbon_gco2"] {
		t.Errorf("expected identical total_carbon_gco2, got call1=%v, call2=%v", sum1["total_carbon_gco2"], sum2["total_carbon_gco2"])
	}
	if sum1["water_usage_liters"] != sum2["water_usage_liters"] {
		t.Errorf("expected identical water_usage_liters, got call1=%v, call2=%v", sum1["water_usage_liters"], sum2["water_usage_liters"])
	}

	ts1 := call1["timeseries"].([]EnergyTimePoint)
	ts2 := call2["timeseries"].([]EnergyTimePoint)
	if len(ts1) != 31 || len(ts2) != 31 {
		t.Errorf("expected exactly 31 points for July 2026, got %d and %d", len(ts1), len(ts2))
	}
	for i := range ts1 {
		if ts1[i].Watts != ts2[i].Watts || ts1[i].Time != ts2[i].Time {
			t.Errorf("point %d mismatch: %+v vs %+v", i, ts1[i], ts2[i])
		}
	}

	// 2. Échelonnage logique de l'énergie : 7j (168h) vs 30j (720h)
	res7d, _ := svc.GetEnergyTelemetry("7d", "", "", "", "", "all", "all")
	res30d, _ := svc.GetEnergyTelemetry("30d", "", "", "", "", "all", "all")
	kwh7d := res7d["summary"].(map[string]any)["total_kwh"].(float64)
	kwh30d := res30d["summary"].(map[string]any)["total_kwh"].(float64)
	if kwh30d <= kwh7d {
		t.Errorf("expected 30d total_kwh (%v) > 7d total_kwh (%v)", kwh30d, kwh7d)
	}

	// 3. Export CSV certifié RSE
	var buf strings.Builder
	err = svc.ExportEnergyCSV(&buf, "month", "", "", "2026-07", "", "all", "all")
	if err != nil {
		t.Fatalf("ExportEnergyCSV error: %v", err)
	}
	csvContent := buf.String()
	if !strings.Contains(csvContent, "RAPPORT D'AUDIT RSE & BILAN CARBONE GREENOPS") {
		t.Errorf("expected CSRD header in CSV, got: %s", csvContent[:200])
	}
	if !strings.Contains(csvContent, "Mois de 2026-07") {
		t.Errorf("expected 'Mois de 2026-07' in CSV metadata")
	}
	if !strings.Contains(csvContent, "Intel/AMD RAPL MSR") {
		t.Errorf("expected RAPL MSR hardware probe mention in CSV")
	}
}


