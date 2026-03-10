package policy

import (
	"fmt"
	"regexp"
)

type Rule struct {
	Role    string   `yaml:"role"`
	Path    string   `yaml:"path"`
	Methods []string `yaml:"methods"`
	Backend string   `yaml:"backend"`
}

// CompiledRule holds the pre-compiled regix to ensure ultra fast routing.
type CompiledRule struct {
	Role      string
	PathRegex *regexp.Regexp // The compiled state machine
	Methods   []string
	Backend   string
}

type Engine struct {
	rules []CompiledRule
}

func NewEngine(rules []Rule) (*Engine, error) {
	var compiled_rules []CompiledRule

	for _, r := range rules {
		// Compile the path string into and excutable regular expression
		re, err := regexp.Compile(r.Path)
		if err != nil {
			return nil, fmt.Errorf("Fetal: Invalid regex pattern in policy for path '%s': %v", r.Path, err)
		}

		compiled_rules = append(compiled_rules, CompiledRule{
			Role:      r.Role,
			PathRegex: re,
			Methods:   r.Methods,
			Backend:   r.Backend,
		})
	}
	return &Engine{rules: compiled_rules}, nil
}

// MapRequest checks authorization and returns the target backend URL if allowed.
func (e *Engine) MapRequest(role, path, method string) (string, bool) {
	for _, rule := range e.rules {
		// In a real military system, we would use regex or prefix matching for paths.
		// For now, we do exact match.
		if rule.Role == role && rule.PathRegex.MatchString(path) {
			for _, m := range rule.Methods {
				if m == method || m == "*" {
					return rule.Backend, true
				}
			}
		}
	}
	return "", false
}
