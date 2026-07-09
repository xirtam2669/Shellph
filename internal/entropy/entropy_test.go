package entropy

import (
	"testing"
	"math"
	)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want float64
	}{
		{"empty", []byte{}, 0.0},
		{"single byte", []byte{0x00}, 0.0},
		{"two bytes", []byte{0x00, 0x01}, 1.0},
		{"uniform distribution", []byte{0x00, 0x01, 0x02, 0x03}, 2.0},
		{"non-uniform distribution", []byte{0x00, 0x00, 0x01, 0x01}, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateEntropy(tt.data)
			if math.Abs(got-tt.want) > 1e-6 {
				t.Errorf("CalculateEntropy() = %f, want %f", got, tt.want)
			}
		})
	}
}