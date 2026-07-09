package entropy

import (
	"math"
)

func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	// Calculate the frequency of each byte value in the data
	var frequencies = make([]float64, 256)
	for _, b := range data {
		frequencies[b]++
	}


	var entropy float64
	length := float64(len(data))

	for _, count := range frequencies {
		if count > 0 {
			probability := count / length
			entropy -= probability * math.Log2(probability)
		}
	}
	return entropy
}
