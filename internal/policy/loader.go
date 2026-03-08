package policy

import (
	"os"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Policies []Rule `yaml:"policies"`
}

func LoadFromYAML(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
