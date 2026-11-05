package httputil

import (
	"testing"
)

func TestHelpers(t *testing.T) {
	m := map[string]any{
		"str_key":   "hello",
		"int_key":   42,
		"float_key": 3.14,
		"bool_key":  true,
		"str_bool":  "yes",
	}

	if got := AsString(m, "str_key", "default"); got != "hello" {
		t.Errorf("AsString() = %v, want hello", got)
	}
	if got := AsString(m, "missing", "default"); got != "default" {
		t.Errorf("AsString() missing = %v, want default", got)
	}

	if got := AsInt(m, "int_key", 0); got != 42 {
		t.Errorf("AsInt() = %v, want 42", got)
	}
	if got := AsInt(m, "missing", 10); got != 10 {
		t.Errorf("AsInt() missing = %v, want 10", got)
	}

	if got := AsFloat(m, "float_key", 0); got != 3.14 {
		t.Errorf("AsFloat() = %v, want 3.14", got)
	}

	if got := AsBool(m, "bool_key", false); got != true {
		t.Errorf("AsBool() = %v, want true", got)
	}
	if got := AsBool(m, "str_bool", false); got != true {
		t.Errorf("AsBool() str_bool = %v, want true", got)
	}
}
