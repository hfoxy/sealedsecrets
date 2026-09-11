package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestDecodeManifest(t *testing.T) {
	resource := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: example\n"
	for _, test := range []struct {
		name, input string
		valid       bool
	}{
		{"yaml", resource, true},
		{"json", `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"example"}}`, true},
		{"empty documents", "---\n# empty\n---\n" + resource + "---\n# trailing\n", true},
		{"empty", "", false},
		{"comment", "# empty\n", false},
		{"invalid", "[", false},
		{"multiple resources", resource + "---\n" + resource, false},
		{"invalid trailing document", resource + "---\n[", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var secret corev1.Secret
			err := decodeManifest([]byte(test.input), &secret)
			if (err == nil) != test.valid {
				t.Fatalf("error = %v, want valid = %v", err, test.valid)
			}
			if test.valid && secret.Name != "example" {
				t.Fatalf("name = %q", secret.Name)
			}
		})
	}
}
