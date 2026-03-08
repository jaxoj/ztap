package policy_test

import (
	"os"
	"path/filepath"
	"testing"
	"ztap/internal/policy"
)

const yamlContent = `
policies:
  - role: "field_officer"
    path: "/api/v1/intel"
    methods: ["GET"]
  - role: "commander"
    path: "/api/v1/launch"
    methods: ["POST"]
`

// Used to prepare the YAML file for testing.
func PrepareYAMLFile(t *testing.T) string {
	// This function can be used to prepare the YAML file if needed.
	// For this example, we assume the file already exists in testdata/policy.yaml.
	tempYAMLFile := filepath.Join(t.TempDir(), "policy.yaml")

	err := os.WriteFile(tempYAMLFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write YAML file: %v", err)
	}

	return tempYAMLFile
}

func TestLoadFromYAML(t *testing.T) {
	tempYAMLFile := PrepareYAMLFile(t)
	plcs, err := policy.LoadFromYAML(tempYAMLFile)
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	if len(plcs.Policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(plcs.Policies))
	}
}
