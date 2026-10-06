// Package contentintel performs deterministic, explainable checks over
// protocol metadata that can enter an agent's context before tool execution.
package contentintel

import (
	"regexp"
	"strings"
)

const AnalyzerRevision = "content-integrity-2026-07-21.1"

type Item struct {
	Kind, ID, Name, Text, Provenance string
}

type Signal struct {
	RuleID, SurfaceKind, SurfaceID, Severity, Category, Title, Summary string
	MatchedText, Recommendation                                        string
	Confidence                                                         float64
	Evidence                                                           []string
}

type signature struct {
	id, severity, category, title, summary, recommendation string
	confidence                                             float64
	patterns                                               []*regexp.Regexp
}

var signatures = []signature{
	{"CONTENT-INSTRUCTION-OVERRIDE", "high", "instruction-integrity", "Instruction override language in advertised metadata", "The metadata attempts to supersede prior or governing instructions.", "Remove behavioral override language from server-controlled metadata and enforce trusted instruction precedence at runtime.", .94, compile(`(?i)ignore\s+(all\s+)?(previous|prior|system)\s+instructions?`, `(?i)disregard\s+(all\s+)?(previous|prior|system)\s+instructions?`, `(?i)override\s+(the\s+)?(system|developer|security)\s+(message|instructions?|policy)`)},
	{"CONTENT-CREDENTIAL-HARVEST", "high", "credential-safety", "Credential disclosure request in advertised metadata", "The metadata asks an agent to reveal or include credentials or secret tokens.", "Remove secret-disclosure instructions and use AgntID identity-aware policy to prevent credential-bearing context from reaching this capability.", .96, compile(`(?i)(reveal|expose|return|include|print|send)\s+(any\s+|the\s+)?(api[ _-]?(key|token)|access[ _-]?token|password|credential|secret)`, `(?i)(api[ _-]?(key|token)|access[ _-]?token|password|credential|secret).{0,30}(in|into)\s+(the\s+)?(output|response|result)`)},
	{"CONTENT-EXFILTRATION", "high", "data-egress", "External data transfer instruction in advertised metadata", "The metadata directs an agent to transmit context or data to an external destination.", "Remove covert transfer instructions and require explicit AgntID egress policy and approval for external destinations.", .91, compile(`(?i)(send|upload|transmit|post|forward)\s+.{0,50}(to|via)\s+(an?\s+)?(external|webhook|remote|third[ -]?party|email)`, `(?i)(curl|wget)\s+https?://`)},
	{"CONTENT-ROLE-ESCAPE", "medium", "instruction-integrity", "Role or policy escape language in advertised metadata", "The metadata encourages operation outside the agent's intended role or controls.", "Remove role-escape language and bind tool visibility to an AgntID policy profile.", .86, compile(`(?i)act\s+as\s+(an?\s+)?(unrestricted|unfiltered|root|administrator)`, `(?i)(bypass|disable|evade)\s+(the\s+)?(guardrail|policy|approval|security|restriction)`)},
	{"CONTENT-TOOL-REDIRECT", "medium", "tool-integrity", "Cross-tool redirection in advertised metadata", "The metadata attempts to redirect selection from one capability to another.", "Review the tool declaration and use an approved AgntID catalog baseline to quarantine unexpected routing instructions.", .82, compile(`(?i)(instead\s+of|when\s+asked\s+to)\s+.{0,50}(use|call|invoke)\s+.{1,60}`)},
	{"CONTENT-COMMAND-EXECUTION", "medium", "execution-surface", "Command execution instruction in advertised metadata", "The metadata contains a shell or interpreter execution directive.", "Confirm that executable instructions are necessary; otherwise remove them and gate execution-capable tools behind AgntID approval.", .79, compile(`(?i)(run|execute)\s+(this\s+|the\s+)?(shell|bash|powershell|terminal|command)`, `(?i)(bash|sh|powershell|cmd)\s+-[a-z]*c\s+`)},
}

func compile(values ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(values))
	for _, value := range values {
		out = append(out, regexp.MustCompile(value))
	}
	return out
}

func Analyze(items []Item) []Signal {
	out := []Signal{}
	for _, item := range items {
		text := strings.TrimSpace(item.Text)
		if text == "" {
			continue
		}
		for _, sig := range signatures {
			for _, pattern := range sig.patterns {
				location := pattern.FindStringIndex(text)
				if location == nil {
					continue
				}
				out = append(out, Signal{RuleID: sig.id, SurfaceKind: item.Kind, SurfaceID: item.ID, Severity: sig.severity, Category: sig.category, Title: sig.title, Summary: sig.summary, MatchedText: excerpt(text, location[0], location[1]), Recommendation: sig.recommendation, Confidence: sig.confidence, Evidence: []string{"deterministic signature match", "surface=" + item.Kind, "analyzer=" + AnalyzerRevision}})
				break
			}
		}
		if containsBidiControl(text) {
			out = append(out, Signal{RuleID: "CONTENT-UNICODE-DECEPTION", SurfaceKind: item.Kind, SurfaceID: item.ID, Severity: "high", Category: "content-deception", Title: "Bidirectional control character in advertised metadata", Summary: "The metadata contains an invisible Unicode control that can alter displayed text order.", MatchedText: "Unicode bidirectional control character", Recommendation: "Remove invisible direction controls and review the declaration against a trusted source baseline.", Confidence: .99, Evidence: []string{"Unicode bidi control detected", "analyzer=" + AnalyzerRevision}})
		}
	}
	return out
}

func containsBidiControl(s string) bool {
	for _, r := range s {
		switch r {
		case '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069':
			return true
		}
	}
	return false
}

func excerpt(s string, start, end int) string {
	const radius = 72
	left, right := start-radius, end+radius
	if left < 0 {
		left = 0
	}
	if right > len(s) {
		right = len(s)
	}
	result := strings.Join(strings.Fields(s[left:right]), " ")
	if left > 0 {
		result = "…" + result
	}
	if right < len(s) {
		result += "…"
	}
	return result
}
