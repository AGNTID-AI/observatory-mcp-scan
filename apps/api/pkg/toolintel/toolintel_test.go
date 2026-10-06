package toolintel

import "testing"

func boolPtr(value bool) *bool { return &value }

func TestDestructiveToolClassificationAndPolicy(t *testing.T) {
	tool := Tool{
		Name:        "delete_customer_records",
		Description: "Permanently delete all customer records for a tenant.",
		InputSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string", "description": "Tenant identifier"},
			},
			"required": []any{"tenant_id"},
		},
		Annotations: Annotations{ReadOnlyHint: boolPtr(true), DestructiveHint: boolPtr(false)},
	}
	analysis := Analyze(tool)
	if analysis.Classification.OperationType != "DELETE" {
		t.Fatalf("operation = %s, want DELETE", analysis.Classification.OperationType)
	}
	if !contains(analysis.Classification.Effects, "DESTRUCTIVE") {
		t.Fatalf("effects = %v, want DESTRUCTIVE", analysis.Classification.Effects)
	}
	if len(analysis.Classification.AnnotationContradictions) != 2 {
		t.Fatalf("contradictions = %v", analysis.Classification.AnnotationContradictions)
	}
	if analysis.Policy["read-only"].Disposition != "hidden" {
		t.Fatalf("read-only disposition = %s", analysis.Policy["read-only"].Disposition)
	}
	if analysis.Policy["protected"].Disposition != "approval" {
		t.Fatalf("protected disposition = %s", analysis.Policy["protected"].Disposition)
	}
}

func TestSchemaAnalysisFindsLooseDangerousStrings(t *testing.T) {
	analysis := AnalyzeSchema(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"command": map[string]any{"type": "string"},
			"token":   map[string]any{"type": "string", "description": "API token"},
		},
	}, nil)
	if analysis.AdditionalProperties != "unspecified" {
		t.Fatalf("additionalProperties = %s", analysis.AdditionalProperties)
	}
	if analysis.UnconstrainedStringCount != 2 {
		t.Fatalf("unconstrained strings = %d", analysis.UnconstrainedStringCount)
	}
	if len(analysis.SensitiveFields) != 1 || len(analysis.DangerousFields) != 1 {
		t.Fatalf("sensitive=%v dangerous=%v", analysis.SensitiveFields, analysis.DangerousFields)
	}
	if len(analysis.InputRisks) != 2 {
		t.Fatalf("input risks=%v, want command and credential boundaries", analysis.InputRisks)
	}
}

func TestInputRiskDistinguishesCredentialValuesFromIdentifiers(t *testing.T) {
	analysis := AnalyzeSchema(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"secret_id":    map[string]any{"type": "string", "description": "Secret identifier"},
			"access_token": map[string]any{"type": "string", "description": "Bearer access token"},
			"target_url":   map[string]any{"type": "string", "description": "Destination URL"},
			"safe_url":     map[string]any{"type": "string", "format": "uri", "description": "Validated callback URL"},
		},
	}, nil)
	kinds := map[string]InputRisk{}
	for _, risk := range analysis.InputRisks {
		kinds[risk.Path+":"+risk.Kind] = risk
	}
	if _, exists := kinds["$.secret_id:CREDENTIAL"]; exists {
		t.Fatal("credential identifier was treated as credential material")
	}
	if _, exists := kinds["$.access_token:CREDENTIAL"]; !exists {
		t.Fatal("credential value was not identified")
	}
	if risk, exists := kinds["$.target_url:URL"]; !exists || risk.Constrained {
		t.Fatalf("unconstrained URL risk missing: %#v", risk)
	}
	if risk, exists := kinds["$.safe_url:URL"]; !exists || !risk.Constrained {
		t.Fatalf("declared URL constraint missing: %#v", risk)
	}
}

func TestCatalogFingerprintStableAcrossOrdering(t *testing.T) {
	a := Tool{Name: "a", InputSchema: map[string]any{"type": "object"}}
	b := Tool{Name: "b", InputSchema: map[string]any{"type": "object"}}
	if CatalogFingerprint([]Tool{a, b}) != CatalogFingerprint([]Tool{b, a}) {
		t.Fatal("catalog fingerprint changed with tool ordering")
	}
}

func TestOperationKeywordsUseTokenBoundaries(t *testing.T) {
	result := Analyze(Tool{Name: "list_cloud_assets", Description: "List assets visible to the tenant", InputSchema: map[string]any{"type": "object"}})
	if result.Classification.OperationType != "LIST" {
		t.Fatalf("assets must not match the write keyword set: got %s", result.Classification.OperationType)
	}
}

func TestPluralDomainAndRotateOperation(t *testing.T) {
	read := Analyze(Tool{Name: "search_customer_records", Description: "Search customer records", InputSchema: map[string]any{"type": "object"}})
	if read.Classification.Domain != "DATABASE" || read.Classification.Sensitivity != "HIGH" {
		t.Fatalf("plural records should identify sensitive database access: domain=%s sensitivity=%s", read.Classification.Domain, read.Classification.Sensitivity)
	}
	rotate := Analyze(Tool{Name: "rotate_service_credential", Description: "Rotate a credential", InputSchema: map[string]any{"type": "object"}})
	if rotate.Classification.OperationType != "WRITE" {
		t.Fatalf("rotate should be a WRITE operation, got %s", rotate.Classification.OperationType)
	}
}

func TestSecretScanningContentIsNotCredentialOrPathInput(t *testing.T) {
	readOnly := true
	openWorld := false
	analysis := Analyze(Tool{
		Name:        "run_secret_scanning",
		Description: "Scan files, content, or recent changes for secrets such as API keys, passwords, tokens, and credentials. This tool performs targeted scans of specific files, snippets, or diff hunks supplied as content.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"files": map[string]any{
					"description": "A string or array containing raw file contents, snippets, or diff hunks to scan for secrets. These are raw contents, not repository file paths.",
				},
			},
		},
		Annotations: Annotations{ReadOnlyHint: &readOnly, OpenWorldHint: &openWorld},
	})
	if analysis.Classification.OperationType != "LIST" || analysis.Classification.IsMutating {
		t.Fatalf("secret scanning should be read-only discovery: operation=%s mutating=%t", analysis.Classification.OperationType, analysis.Classification.IsMutating)
	}
	if contains(analysis.Classification.Effects, "CREDENTIAL_ACCESS") {
		t.Fatalf("secret scanning content was treated as credential access: %v", analysis.Classification.Effects)
	}
	if analysis.Classification.Domain != "FILESYSTEM" || analysis.Classification.Sensitivity != "HIGH" || analysis.Classification.BlastRadius != "MULTI_RECORD" {
		t.Fatalf("secret scanning context was misclassified: domain=%s sensitivity=%s blast=%s", analysis.Classification.Domain, analysis.Classification.Sensitivity, analysis.Classification.BlastRadius)
	}
	for _, evidence := range analysis.Classification.Evidence {
		if evidence == "mutating operation targets a service-level resource" || evidence == "credential or secret access signal" {
			t.Fatalf("secret scanning retained contradictory evidence: %v", analysis.Classification.Evidence)
		}
	}
	if len(analysis.Classification.AnnotationContradictions) != 0 {
		t.Fatalf("read-only secret scanning produced annotation conflict: %v", analysis.Classification.AnnotationContradictions)
	}
	for _, risk := range analysis.Schema.InputRisks {
		if risk.Path == "$.files" && (risk.Kind == "CREDENTIAL" || risk.Kind == "PATH") {
			t.Fatalf("raw scan content was treated as %s input: %#v", risk.Kind, risk)
		}
	}
	if analysis.Policy["read-only"].Disposition != "visible" || analysis.Policy["read-write"].Disposition != "visible" || analysis.Policy["protected"].RequiresApproval {
		t.Fatalf("read-only scanner received restrictive policy: %#v", analysis.Policy)
	}
}

func TestLeadingReadVerbWinsOverResourceNoun(t *testing.T) {
	readOnly := true
	analysis := Analyze(Tool{
		Name:        "get_status_updates",
		Description: "List or get project status updates.",
		InputSchema: map[string]any{"type": "object"},
		Annotations: Annotations{ReadOnlyHint: &readOnly},
	})
	if analysis.Classification.OperationType != "READ" || analysis.Classification.IsMutating {
		t.Fatalf("status-update reader was classified as mutation: %#v", analysis.Classification)
	}
	if len(analysis.Classification.AnnotationContradictions) != 0 {
		t.Fatalf("status-update reader produced annotation conflict: %v", analysis.Classification.AnnotationContradictions)
	}
}

func TestIdempotentDestructiveAnnotationsCanCoexist(t *testing.T) {
	destructive := true
	idempotent := true
	analysis := Analyze(Tool{
		Name:        "resolve_diff_thread",
		Description: "Resolve or reopen a top-level comment thread.",
		InputSchema: map[string]any{"type": "object"},
		Annotations: Annotations{DestructiveHint: &destructive, IdempotentHint: &idempotent},
	})
	if !contains(analysis.Classification.Effects, "DESTRUCTIVE") {
		t.Fatalf("declared destructive effect missing: %v", analysis.Classification.Effects)
	}
	if len(analysis.Classification.AnnotationContradictions) != 0 {
		t.Fatalf("idempotent destructive operation was treated as contradictory: %v", analysis.Classification.AnnotationContradictions)
	}
}

func TestAttachmentLabelsAreNotExecutionBoundaries(t *testing.T) {
	analysis := AnalyzeSchema(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"filename": map[string]any{"type": "string", "description": "Filename for the uploaded attachment"},
			"title":    map[string]any{"type": "string", "description": "Defaults to filename or asset URL"},
			"assetUrl": map[string]any{"type": "string", "format": "uri", "description": "Linear upload asset URL"},
			"filePath": map[string]any{"type": "string", "description": "Local file path to read"},
		},
	}, nil)
	kinds := map[string]InputRisk{}
	for _, risk := range analysis.InputRisks {
		kinds[risk.Path+":"+risk.Kind] = risk
	}
	if _, exists := kinds["$.filename:PATH"]; exists {
		t.Fatal("attachment filename was treated as a filesystem path")
	}
	if _, exists := kinds["$.title:URL"]; exists {
		t.Fatal("attachment title was treated as a network destination")
	}
	if risk, exists := kinds["$.assetUrl:URL"]; !exists || !risk.Constrained {
		t.Fatalf("asset URL boundary missing or unconstrained: %#v", risk)
	}
	if _, exists := kinds["$.filePath:PATH"]; !exists {
		t.Fatal("actual file-path boundary was not detected")
	}
}

func TestCredentialContextDoesNotImplyCredentialAccess(t *testing.T) {
	readOnly := true
	analysis := Analyze(Tool{
		Name:        "get_team_members",
		Description: "Get team members for organizations accessible with current credentials.",
		InputSchema: map[string]any{"type": "object"},
		Annotations: Annotations{ReadOnlyHint: &readOnly},
	})
	if contains(analysis.Classification.Effects, "CREDENTIAL_ACCESS") || analysis.Classification.Sensitivity == "CRITICAL" {
		t.Fatalf("credential context was treated as credential material: effects=%v sensitivity=%s", analysis.Classification.Effects, analysis.Classification.Sensitivity)
	}
	if analysis.Policy["protected"].RequiresApproval {
		t.Fatalf("ordinary read was approval-gated: %#v", analysis.Policy["protected"])
	}
}

func TestRepositoryReadDoesNotRequireProtectedApproval(t *testing.T) {
	readOnly := true
	analysis := Analyze(Tool{
		Name:        "list_branches",
		Description: "List branches in a GitHub repository.",
		InputSchema: map[string]any{"type": "object"},
		Annotations: Annotations{ReadOnlyHint: &readOnly},
	})
	if analysis.Classification.BlastRadius != "SERVICE_WIDE" {
		t.Fatalf("expected repository-wide read, got %s", analysis.Classification.BlastRadius)
	}
	if analysis.Policy["protected"].RequiresApproval {
		t.Fatalf("repository-wide read was approval-gated: %#v", analysis.Policy["protected"])
	}
}
