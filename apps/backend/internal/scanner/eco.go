package scanner

import "math"

var (
	quantilesDOM = []float64{
		0, 47, 75, 159, 233, 298, 358, 417, 476, 537,
		603, 674, 753, 843, 949, 1076, 1237, 1459, 1801, 2479, 594601,
	}
	quantilesReq = []float64{
		0, 2, 15, 25, 34, 42, 49, 56, 63, 70,
		78, 86, 95, 105, 117, 130, 147, 170, 205, 281, 3920,
	}
	quantilesSize = []float64{
		0, 1.37, 144.7, 319.53, 479.46, 631.97, 783.38, 937.91, 1098.62, 1265.47,
		1448.32, 1648.27, 1876.08, 2142.06, 2465.37, 2866.31, 3401.59, 4155.73, 5400.08, 8037.54, 223212.26,
	}
)

func getQuantile(quantiles []float64, value float64) float64 {
	for i := 1; i < len(quantiles); i++ {
		if value < quantiles[i] {
			return float64(i-1) + (value-quantiles[i-1])/(quantiles[i]-quantiles[i-1])
		}
	}
	return float64(len(quantiles) - 1)
}

// CalculateEcoScore calcule l'EcoIndex selon la formule officielle GreenIT standard (0 à 100)
// basée sur les quantiles de poids (Ko), du nombre d'éléments DOM et de requêtes HTTP.
func CalculateEcoScore(weightKB float64, domElements, httpRequests int) (score float64, grade string, gco2 float64, waterCL float64) {
	qDom := getQuantile(quantilesDOM, float64(domElements))
	qReq := getQuantile(quantilesReq, float64(httpRequests))
	qSize := getQuantile(quantilesSize, weightKB)

	rawScore := 100.0 - 5.0*(3.0*qDom+2.0*qReq+qSize)/6.0
	score = roundFloat(math.Max(0.0, math.Min(100.0, rawScore)), 1)
	grade = computeEcoGrade(score)

	// Émissions GES : 2 + 2 * (50 - score) / 100 (gCO2e)
	gco2 = roundFloat(math.Max(0.1, 2.0+2.0*(50.0-score)/100.0), 2)
	// Eau consommée : 3 + 3 * (50 - score) / 100 (cL)
	waterCL = roundFloat(math.Max(0.1, 3.0+3.0*(50.0-score)/100.0), 2)

	return score, grade, gco2, waterCL
}

func computeEcoGrade(score float64) string {
	switch {
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 55:
		return "C"
	case score >= 40:
		return "D"
	case score >= 25:
		return "E"
	case score >= 10:
		return "F"
	default:
		return "G"
	}
}

func roundFloat(val float64, precision int) float64 {
	p := 1.0
	for i := 0; i < precision; i++ {
		p *= 10.0
	}
	return math.Round(val*p) / p
}
