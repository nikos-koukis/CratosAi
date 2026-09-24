package mtls

import "testing"

var methods = []string{"ListTools", "CallTool"}

func TestPolicyGrantsAreExact(t *testing.T) {
	p, err := ParsePolicy(`
		[[principal]]
		id = "spiffe://jarvis.test/orchestrator"
		allow = ["ListTools", "CallTool"]

		[[principal]]
		id = "spiffe://jarvis.test/viewer"
		allow = ["ListTools"]
	`, methods)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed("spiffe://jarvis.test/orchestrator", "CallTool") ||
		p.Allowed("spiffe://jarvis.test/viewer", "CallTool") ||
		p.Allowed("spiffe://jarvis.test/unknown", "ListTools") {
		t.Fatal("grants are not exact")
	}
}

func TestMalformedPoliciesAreRejected(t *testing.T) {
	for name, text := range map[string]string{
		"unknown method": "[[principal]]\nid = \"spiffe://a/b\"\nallow = [\"DropTables\"]",
		"not a uri":      "[[principal]]\nid = \"orchestrator\"\nallow = [\"CallTool\"]",
		"empty allow":    "[[principal]]\nid = \"spiffe://a/b\"\nallow = []",
		"duplicate":      "[[principal]]\nid = \"spiffe://a/b\"\nallow = [\"CallTool\"]\n[[principal]]\nid = \"spiffe://a/b\"\nallow = [\"ListTools\"]",
		"unknown field":  "[[principal]]\nid = \"spiffe://a/b\"\nallow = [\"CallTool\"]\ntenants = [\"*\"]",
		"not toml":       "{",
	} {
		if _, err := ParsePolicy(text, methods); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
