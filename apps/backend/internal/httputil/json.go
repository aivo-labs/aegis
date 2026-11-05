package httputil

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// WriteJSON sérialise un objet en JSON avec en-têtes CORS et sécurité.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-Exploit-Signature, X-Aegis-Payload-Bytes")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

// ReadJSONBody lit et décode un corps JSON avec une limite stricte de taille.
func ReadJSONBody(r *http.Request) map[string]any {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil || len(body) == 0 {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func AsString(m map[string]any, key, def string) string {
	if v, ok := m[key]; ok && v != nil {
		switch val := v.(type) {
		case string:
			if strings.TrimSpace(val) != "" {
				return val
			}
		default:
			return fmt.Sprintf("%v", val)
		}
	}
	return def
}

func AsFloat(m map[string]any, key string, def float64) float64 {
	if v, ok := m[key]; ok && v != nil {
		switch val := v.(type) {
		case float64:
			return val
		case int:
			return float64(val)
		case string:
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				return f
			}
		}
	}
	return def
}

func AsInt(m map[string]any, key string, def int) int {
	if v, ok := m[key]; ok && v != nil {
		switch val := v.(type) {
		case float64:
			return int(val)
		case int:
			return val
		case string:
			if i, err := strconv.Atoi(val); err == nil {
				return i
			}
		}
	}
	return def
}

func AsBool(m map[string]any, key string, def bool) bool {
	if v, ok := m[key]; ok && v != nil {
		switch val := v.(type) {
		case bool:
			return val
		case string:
			low := strings.ToLower(strings.TrimSpace(val))
			return low == "true" || low == "1" || low == "on" || low == "yes"
		}
	}
	return def
}
