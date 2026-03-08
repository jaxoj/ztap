package policy

type Rule struct {
	Role    string
	Path    string
	Methods []string
}

type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

func (e *Engine) IsAllowed(role, path, method string) bool {
	for _, rule := range e.rules {
		if rule.Role == role && rule.Path == path {
			for _, allowedMethod := range rule.Methods {
				if allowedMethod == method || allowedMethod == "*" {
					return true
				}
			}

		}
	}
	// Default deny if no explicit rule allowes it, reject it.
	return false
}
