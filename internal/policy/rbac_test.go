package policy_test

import (
	"testing"
	"ztap/internal/policy"
)

func TestRBACEngine(t *testing.T) {
	// Define our strict military access rules
	rules := []policy.Rule{
		{
			Role:    "field_officer",
			Path:    "/api/v1/intel",
			Methods: []string{"GET"},
		},
		{
			Role:    "commander",
			Path:    "/api/v1/intel",
			Methods: []string{"POST", "GET"},
		},
		{
			Role:    "commander",
			Path:    "/api/v1/launch",
			Methods: []string{"POST"},
		},
	}

	engine := policy.NewEngine(rules)

	tests := []struct {
		name           string
		role           string
		path           string
		method         string
		expectedResult bool
	}{
		{"Field Officer can read intel", "field_officer", "/api/v1/intel", "GET", true},
		{"Field Officer cannot write intel", "field_officer", "/api/v1/intel", "POST", false},
		{"Field Officer cannot launch", "field_officer", "/api/v1/launch", "POST", false},
		{"Commander can write intel", "commander", "/api/v1/intel", "POST", true},
		{"Commander can launch", "commander", "/api/v1/launch", "POST", true},
		{"Unknown role denied everything", "private", "/api/v1/intel", "GET", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.IsAllowed(tt.role, tt.path, tt.method)
			if result != tt.expectedResult {
				t.Errorf("Expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}
