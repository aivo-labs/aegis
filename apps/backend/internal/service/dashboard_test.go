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
