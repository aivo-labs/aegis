package scanner

import (
	"testing"
)

func TestCalculateEcoScore(t *testing.T) {
	tests := []struct {
		name         string
		weightKB     float64
		domElements  int
		httpRequests int
		wantGrade    string
	}{
		{"Lightweight page", 120.0, 150, 10, "A"},
		{"Standard medium page", 800.0, 600, 45, "C"},
		{"Heavy bloated page", 4500.0, 2200, 120, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, grade, gco2, waterCL := CalculateEcoScore(tt.weightKB, tt.domElements, tt.httpRequests)
			if score < 0 || score > 100 {
				t.Errorf("CalculateEcoScore() score = %v, want between 0 and 100", score)
			}
			if grade != tt.wantGrade {
				t.Errorf("CalculateEcoScore() grade = %v, want %v", grade, tt.wantGrade)
			}
			if gco2 <= 0 {
				t.Errorf("CalculateEcoScore() gco2 = %v, want > 0", gco2)
			}
			if waterCL <= 0 {
				t.Errorf("CalculateEcoScore() waterCL = %v, want > 0", waterCL)
			}
		})
	}
}

func TestComputeEcoGrade(t *testing.T) {
	cases := []struct {
		score float64
		grade string
	}{
		{95.0, "A"},
		{75.0, "B"},
		{60.0, "C"},
		{45.0, "D"},
		{30.0, "E"},
		{15.0, "F"},
		{5.0, "G"},
	}
	for _, c := range cases {
		if got := computeEcoGrade(c.score); got != c.grade {
			t.Errorf("computeEcoGrade(%v) = %v, want %v", c.score, got, c.grade)
		}
	}
}
