package engine

import (
	"strings"
	"testing"

	mcpv1 "jarvis.internal/gen/go/jarvis/mcp/v1"
	"jarvis.internal/orchestrator/internal/store"
)

func TestToolNamesAreSafeAndUnique(t *testing.T) {
	c := &catalog{targets: map[string]store.Target{}}
	tools := []*mcpv1.Tool{
		{IntegrationName: "Δουλειά Jira!!", Name: "create.issue/v2", InputSchemaJson: `{"type":"object"}`},
		{IntegrationName: "Δουλειά Jira!!", Name: "create.issue/v2", InputSchemaJson: `{"type":"object"}`},
		{IntegrationName: strings.Repeat("x", 200), Name: strings.Repeat("y", 200), InputSchemaJson: `{"type":"object"}`},
		{IntegrationName: "Bad", Name: "schema", InputSchemaJson: `{"type":"string"}`},
		{IntegrationName: "Bad", Name: "notjson", InputSchemaJson: `nope`},
	}
	c.integrations(tools, 10)
	if len(c.tools) != 3 {
		t.Fatalf("tools = %d, want 3 (invalid schemas skipped)", len(c.tools))
	}
	seen := map[string]bool{}
	for _, tool := range c.tools {
		if len(tool.GetName()) > 64 || unsafeName.MatchString(tool.GetName()) || seen[tool.GetName()] {
			t.Fatalf("bad or duplicate name %q", tool.GetName())
		}
		seen[tool.GetName()] = true
	}
}

func TestVoiceToolLimitPrefersReadOnly(t *testing.T) {
	c := &catalog{targets: map[string]store.Target{}}
	var tools []*mcpv1.Tool
	for i := range 5 {
		tools = append(tools, &mcpv1.Tool{IntegrationName: "J", Name: "write" + string(rune('a'+i)), InputSchemaJson: `{"type":"object"}`})
	}
	tools = append(tools, &mcpv1.Tool{IntegrationName: "J", Name: "read", InputSchemaJson: `{"type":"object"}`,
		Annotations: &mcpv1.ToolAnnotations{ReadOnly: true}})
	c.integrations(tools, 2)
	if len(c.tools) != 2 || c.targets["j__read"].Kind != kindMCP || !c.targets["j__read"].ReadOnly {
		t.Fatalf("tools = %v", c.targets)
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	for n := range 8 {
		if s := truncate("αβγδ", n); len(s) > n || !strings.HasPrefix("αβγδ", s) {
			t.Fatalf("truncate(%d) = %q", n, s)
		}
	}
}
