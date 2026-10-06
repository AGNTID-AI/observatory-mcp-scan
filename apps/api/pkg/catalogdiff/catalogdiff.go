// Package catalogdiff compares normalized capability declarations without
// coupling the result to MCP or to a persistence implementation.
package catalogdiff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Tool struct {
	Name, Description, Fingerprint, Risk, OperationType string
	InputSchema, OutputSchema                           map[string]any
	Annotations, Classification                         any
}
type Change struct {
	ToolName, ChangeType, Severity, Summary, PolicyImpact, PreviousFingerprint, CurrentFingerprint string
	Fields                                                                                         []string
}
type Result struct {
	PreviousFingerprint, CurrentFingerprint string
	Added, Removed, Modified                int
	Changes                                 []Change
}

func Compare(previous, current []Tool) Result {
	result := Result{PreviousFingerprint: CatalogFingerprint(previous), CurrentFingerprint: CatalogFingerprint(current), Changes: []Change{}}
	old, newer := index(previous), index(current)
	names := map[string]bool{}
	for n := range old {
		names[n] = true
	}
	for n := range newer {
		names[n] = true
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		before, was := old[name]
		after, is := newer[name]
		switch {
		case !was:
			severity := "medium"
			if highRisk(after) {
				severity = "high"
			}
			result.Added++
			result.Changes = append(result.Changes, Change{ToolName: name, ChangeType: "added", Severity: severity, Summary: "A capability appeared that was not present in the prior catalog.", PolicyImpact: addedPolicyImpact(after), CurrentFingerprint: fingerprint(after), Fields: []string{"catalog"}})
		case !is:
			result.Removed++
			result.Changes = append(result.Changes, Change{ToolName: name, ChangeType: "removed", Severity: "low", Summary: "A capability in the prior catalog is no longer advertised.", PolicyImpact: fmt.Sprintf("Check agent workflows and AgntID policies that reference %s; remove or replace the dependency before enforcing the new catalog.", name), PreviousFingerprint: fingerprint(before), Fields: []string{"catalog"}})
		case fingerprint(before) != fingerprint(after):
			fields := changedFields(before, after)
			severity := "medium"
			if highRisk(after) || contains(fields, "classification") || contains(fields, "annotations") {
				severity = "high"
			}
			result.Modified++
			result.Changes = append(result.Changes, Change{ToolName: name, ChangeType: "modified", Severity: severity, Summary: "The advertised declaration changed in " + humanFields(fields) + ".", PolicyImpact: modifiedPolicyImpact(name, fields), PreviousFingerprint: fingerprint(before), CurrentFingerprint: fingerprint(after), Fields: fields})
		}
	}
	return result
}

func addedPolicyImpact(tool Tool) string {
	classification := strings.Trim(strings.ToLower(strings.TrimSpace(tool.OperationType+" / "+tool.Risk)), " /")
	if classification == "" {
		classification = "not yet classified"
	}
	return fmt.Sprintf("%s is new and classified %s. Keep it hidden or approval-gated until its identity exposure, inputs, and effects are reviewed.", tool.Name, classification)
}

func modifiedPolicyImpact(name string, fields []string) string {
	focus := []string{}
	for _, field := range fields {
		switch field {
		case "description":
			focus = append(focus, "recheck when agents should select it")
		case "inputSchema":
			focus = append(focus, "revalidate accepted inputs and constraints")
		case "outputSchema":
			focus = append(focus, "verify consumers and audit handling for the new output")
		case "annotations":
			focus = append(focus, "review changed MCP safety hints")
		case "classification":
			focus = append(focus, "recompute its allow, deny, or approval disposition")
		default:
			focus = append(focus, "review the changed declaration")
		}
	}
	return fmt.Sprintf("The prior decision for %s may be stale: %s.", name, strings.Join(compact(focus), "; "))
}

func humanFields(fields []string) string {
	labels := make([]string, 0, len(fields))
	for _, field := range fields {
		switch field {
		case "inputSchema":
			labels = append(labels, "input schema")
		case "outputSchema":
			labels = append(labels, "output schema")
		default:
			labels = append(labels, field)
		}
	}
	return strings.Join(labels, ", ")
}

func compact(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
func CatalogFingerprint(tools []Tool) string {
	pairs := make([]string, 0, len(tools))
	for _, t := range tools {
		pairs = append(pairs, t.Name+":"+fingerprint(t))
	}
	sort.Strings(pairs)
	h := sha256.Sum256([]byte(strings.Join(pairs, "\n")))
	return hex.EncodeToString(h[:])
}
func index(tools []Tool) map[string]Tool {
	out := map[string]Tool{}
	for _, t := range tools {
		out[t.Name] = t
	}
	return out
}
func fingerprint(t Tool) string {
	if t.Fingerprint != "" {
		return t.Fingerprint
	}
	b, _ := json.Marshal([]any{t.Name, t.Description, t.InputSchema, t.OutputSchema, t.Annotations})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func changedFields(a, b Tool) []string {
	out := []string{}
	if a.Description != b.Description {
		out = append(out, "description")
	}
	if !equal(a.InputSchema, b.InputSchema) {
		out = append(out, "inputSchema")
	}
	if !equal(a.OutputSchema, b.OutputSchema) {
		out = append(out, "outputSchema")
	}
	if !equal(a.Annotations, b.Annotations) {
		out = append(out, "annotations")
	}
	if !equal(a.Classification, b.Classification) || a.OperationType != b.OperationType || a.Risk != b.Risk {
		out = append(out, "classification")
	}
	if len(out) == 0 {
		out = append(out, "declaration")
	}
	return out
}
func equal(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
func highRisk(t Tool) bool {
	v := strings.ToLower(t.Risk + " " + t.OperationType)
	return strings.Contains(v, "high") || strings.Contains(v, "critical") || strings.Contains(v, "delete") || strings.Contains(v, "execute")
}
func contains(values []string, wanted string) bool {
	for _, v := range values {
		if v == wanted {
			return true
		}
	}
	return false
}
