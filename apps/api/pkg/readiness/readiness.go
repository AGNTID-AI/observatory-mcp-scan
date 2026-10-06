// Package readiness evaluates whether tool contracts are precise enough for
// reliable agent selection and safe policy enforcement.
package readiness

import "strings"

const AnalyzerRevision = "contract-readiness-2026-07-21.1"

type Tool struct {
	Name, Description         string
	InputSchema, OutputSchema map[string]any
	Mutating                  bool
	IdempotentHint            *bool
}
type Check struct{ ID, Title, Severity, Status, Evidence, Recommendation string }
type Result struct {
	ToolName string
	Score    int
	Coverage float64
	Grade    string
	Checks   []Check
}

func Analyze(t Tool) Result {
	checks := []Check{}
	add := func(id, title, severity, status, evidence, recommendation string) {
		checks = append(checks, Check{id, title, severity, status, evidence, recommendation})
	}
	desc := strings.TrimSpace(t.Description)
	if len(desc) >= 24 {
		add("description", "Purpose is clearly described", "medium", "pass", "Tool description is specific enough to support selection.", "")
	} else {
		add("description", "Purpose is clearly described", "medium", "fail", "Description is missing or too short to explain when the agent should select this tool.", "Describe the intended outcome, selection boundary, and important side effects.")
	}
	if len(t.OutputSchema) > 0 {
		add("output-schema", "Output contract is advertised", "medium", "pass", "An output schema is present.", "")
	} else {
		add("output-schema", "Output contract is advertised", "medium", "fail", "No output schema was advertised.", "Publish a structured output schema, including stable success and error fields.")
	}
	if additional, ok := t.InputSchema["additionalProperties"]; ok {
		if additional == false {
			add("closed-input", "Input object rejects undeclared fields", "high", "pass", "additionalProperties is explicitly false.", "")
		} else {
			add("closed-input", "Input object rejects undeclared fields", "high", "fail", "The input object permits undeclared fields.", "Set additionalProperties to false unless an open payload is essential.")
		}
	} else {
		add("closed-input", "Input object rejects undeclared fields", "high", "fail", "additionalProperties is not declared, so JSON Schema permits extra fields.", "Set additionalProperties to false and enumerate accepted inputs.")
	}
	props, _ := t.InputSchema["properties"].(map[string]any)
	required := stringSet(t.InputSchema["required"])
	if len(props) == 0 || len(required) == len(props) {
		add("required-inputs", "Required inputs are explicit", "medium", "pass", "All declared inputs are required, or the tool has no inputs.", "")
	} else {
		add("required-inputs", "Required inputs are explicit", "medium", "fail", "Some declared fields are optional without an advertised selection contract.", "Mark essential inputs required and document defaults for optional fields.")
	}
	constrained := constrainedProperties(props)
	if len(props) == 0 || constrained > 0 {
		add("constraints", "Machine-checkable input constraints exist", "medium", "pass", "At least one bounded enum, format, pattern, range, or length constraint is present.", "")
	} else {
		add("constraints", "Machine-checkable input constraints exist", "medium", "fail", "Inputs are described but not bounded with machine-checkable constraints.", "Add enums, formats, patterns, ranges, or length constraints where applicable.")
	}
	if t.Mutating {
		if t.IdempotentHint == nil {
			add("idempotency", "Mutation retry semantics are declared", "medium", "not-observed", "The declaration does not state whether repeating the operation is safe.", "Declare idempotency and enforce a request key for retryable mutations.")
		} else if *t.IdempotentHint {
			add("idempotency", "Mutation retry semantics are declared", "medium", "pass", "The tool advertises idempotent behavior.", "")
		} else {
			add("idempotency", "Mutation retry semantics are declared", "medium", "pass", "The tool explicitly advertises non-idempotent behavior.", "")
		}
	} else {
		add("idempotency", "Mutation retry semantics are declared", "medium", "not-applicable", "The tool is not classified as mutating.", "")
	}

	score, assessed, total := 100, 0, 0
	for _, c := range checks {
		if c.Status == "not-applicable" {
			continue
		}
		total++
		if c.Status == "not-observed" {
			continue
		}
		assessed++
		if c.Status == "fail" {
			if c.Severity == "high" {
				score -= 24
			} else {
				score -= 14
			}
		}
	}
	if score < 0 {
		score = 0
	}
	coverage := float64(assessed) * 100 / float64(total)
	grade := "Needs work"
	if score >= 85 {
		grade = "Strong"
	} else if score >= 70 {
		grade = "Developing"
	}
	return Result{ToolName: t.Name, Score: score, Coverage: coverage, Grade: grade, Checks: checks}
}

func stringSet(value any) map[string]bool {
	out := map[string]bool{}
	switch values := value.(type) {
	case []string:
		for _, v := range values {
			out[v] = true
		}
	case []any:
		for _, v := range values {
			if s, ok := v.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}
func constrainedProperties(props map[string]any) int {
	n := 0
	for _, raw := range props {
		p, _ := raw.(map[string]any)
		for _, key := range []string{"enum", "const", "format", "pattern", "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems"} {
			if _, ok := p[key]; ok {
				n++
				break
			}
		}
	}
	return n
}
