package main

import (
	"os"
	"path/filepath"
	"testing"
)

const pathTestSecret = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: example\nstringData:\n  value: synthetic\n"
const pathTestSealedSecret = "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: example\nspec:\n  encryptedData: {}\n"

func TestResolveSecretPaths(t *testing.T) {
	tests := []struct {
		name        string
		sealing     bool
		arg         string
		output      string
		files       map[string]string
		source      string
		destination string
	}{
		{
			name: "unseal conventional YAML", arg: "secrets.yaml",
			files:  map[string]string{"secrets.yaml": pathTestSealedSecret},
			source: "secrets.yaml", destination: "secrets.unsealed.yaml",
		},
		{
			name: "seal explicit plaintext YAML", sealing: true, arg: "secrets.unsealed.yaml",
			files:  map[string]string{"secrets.unsealed.yaml": pathTestSecret},
			source: "secrets.unsealed.yaml", destination: "secrets.yaml",
		},
		{
			name: "seal by existing destination", sealing: true, arg: "secrets.yaml",
			files:  map[string]string{"secrets.yaml": pathTestSealedSecret, "secrets.unsealed.yaml": pathTestSecret},
			source: "secrets.unsealed.yaml", destination: "secrets.yaml",
		},
		{
			name: "seal by missing destination", sealing: true, arg: "secrets.yaml",
			files:  map[string]string{"secrets.unsealed.yaml": pathTestSecret},
			source: "secrets.unsealed.yaml", destination: "secrets.yaml",
		},
		{
			name: "unseal by existing destination", arg: "secrets.unsealed.yaml",
			files:  map[string]string{"secrets.yaml": pathTestSealedSecret, "secrets.unsealed.yaml": pathTestSecret},
			source: "secrets.yaml", destination: "secrets.unsealed.yaml",
		},
		{
			name: "unseal by missing destination", arg: "secrets.unsealed.yaml",
			files:  map[string]string{"secrets.yaml": pathTestSealedSecret},
			source: "secrets.yaml", destination: "secrets.unsealed.yaml",
		},
		{
			name: "plaintext conventional name stays source", sealing: true, arg: "secrets.yaml",
			files:  map[string]string{"secrets.yaml": pathTestSecret, "secrets.unsealed.yaml": pathTestSecret},
			source: "secrets.yaml", destination: "secrets.sealed.yaml",
		},
		{
			name: "unseal marked sealed name", arg: "secrets.sealed.yaml",
			files:  map[string]string{"secrets.sealed.yaml": pathTestSealedSecret},
			source: "secrets.sealed.yaml", destination: "secrets.unsealed.yaml",
		},
		{
			name: "seal marked sealed destination", sealing: true, arg: "secrets.sealed.yaml",
			files:  map[string]string{"secrets.sealed.yaml": pathTestSealedSecret, "secrets.unsealed.yaml": pathTestSecret},
			source: "secrets.unsealed.yaml", destination: "secrets.sealed.yaml",
		},
		{
			name: "unseal YML", arg: "secrets.yml",
			files:  map[string]string{"secrets.yml": pathTestSealedSecret},
			source: "secrets.yml", destination: "secrets.unsealed.yml",
		},
		{
			name: "seal plaintext YML", sealing: true, arg: "secrets.unsealed.yml",
			files:  map[string]string{"secrets.unsealed.yml": pathTestSecret},
			source: "secrets.unsealed.yml", destination: "secrets.yml",
		},
		{
			name: "seal by YML destination", sealing: true, arg: "secrets.yml",
			files:  map[string]string{"secrets.yml": pathTestSealedSecret, "secrets.unsealed.yml": pathTestSecret},
			source: "secrets.unsealed.yml", destination: "secrets.yml",
		},
		{
			name: "plaintext YML conventional name", sealing: true, arg: "secrets.yml",
			files:  map[string]string{"secrets.yml": pathTestSecret},
			source: "secrets.yml", destination: "secrets.sealed.yml",
		},
		{
			name: "seal extensionless plaintext", sealing: true, arg: "secrets",
			files:  map[string]string{"secrets": pathTestSecret},
			source: "secrets", destination: "secrets.yaml",
		},
		{
			name: "unseal extensionless sealed source", arg: "secrets",
			files:  map[string]string{"secrets": pathTestSealedSecret},
			source: "secrets", destination: "secrets.unsealed.yaml",
		},
		{
			name: "seal by extensionless destination", sealing: true, arg: "secrets",
			files:  map[string]string{"secrets": pathTestSealedSecret, "secrets.unsealed.yaml": pathTestSecret},
			source: "secrets.unsealed.yaml", destination: "secrets",
		},
		{
			name: "explicit output with plaintext source", sealing: true, arg: "secrets.yaml", output: "custom.yml",
			files:  map[string]string{"secrets.yaml": pathTestSecret},
			source: "secrets.yaml", destination: "custom.yml",
		},
		{
			name: "explicit output with inferred plaintext source", sealing: true, arg: "secrets.yaml", output: "custom.yml",
			files:  map[string]string{"secrets.yaml": pathTestSealedSecret, "secrets.unsealed.yaml": pathTestSecret},
			source: "secrets.unsealed.yaml", destination: "custom.yml",
		},
		{
			name: "explicit output with sealed source", arg: "secrets.yaml", output: "custom.yml",
			files:  map[string]string{"secrets.yaml": pathTestSealedSecret},
			source: "secrets.yaml", destination: "custom.yml",
		},
		{
			name: "explicit output with inferred sealed source", arg: "secrets.unsealed.yaml", output: "custom.yml",
			files:  map[string]string{"secrets.yaml": pathTestSealedSecret, "secrets.unsealed.yaml": pathTestSecret},
			source: "secrets.yaml", destination: "custom.yml",
		},
		{
			name: "existing output is allowed by resolver", sealing: true, arg: "secrets.unsealed.yaml",
			files:  map[string]string{"secrets.unsealed.yaml": pathTestSecret, "secrets.yaml": pathTestSealedSecret},
			source: "secrets.unsealed.yaml", destination: "secrets.yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writePathTestFiles(t, dir, tt.files)
			output := ""
			if tt.output != "" {
				output = filepath.Join(dir, tt.output)
			}
			source, destination, err := resolveSecretPaths(filepath.Join(dir, tt.arg), output, tt.sealing)
			if err != nil {
				t.Fatal(err)
			}
			if source != filepath.Join(dir, tt.source) || destination != filepath.Join(dir, tt.destination) {
				t.Fatalf("resolved %q -> %q, want %q -> %q", source, destination, filepath.Join(dir, tt.source), filepath.Join(dir, tt.destination))
			}
		})
	}
}

func TestResolveSecretPathsRejectsInvalidInputs(t *testing.T) {
	wrongKind := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: example\n"
	wrongVersion := "apiVersion: example.com/v1\nkind: Secret\nmetadata:\n  name: example\n"
	tests := []struct {
		name    string
		sealing bool
		arg     string
		files   map[string]string
	}{
		{name: "missing input and sibling", sealing: true, arg: "secrets.yaml"},
		{name: "sealed argument without plaintext sibling", sealing: true, arg: "secrets.yaml", files: map[string]string{"secrets.yaml": pathTestSealedSecret}},
		{name: "plaintext argument without sealed sibling", arg: "secrets.unsealed.yaml", files: map[string]string{"secrets.unsealed.yaml": pathTestSecret}},
		{name: "plaintext sibling has sealed kind", sealing: true, arg: "secrets.yaml", files: map[string]string{"secrets.yaml": pathTestSealedSecret, "secrets.unsealed.yaml": pathTestSealedSecret}},
		{name: "sealed sibling has plaintext kind", arg: "secrets.unsealed.yaml", files: map[string]string{"secrets.unsealed.yaml": pathTestSecret, "secrets.yaml": pathTestSecret}},
		{name: "missing literal with wrong kind sibling", sealing: true, arg: "secrets.yaml", files: map[string]string{"secrets.unsealed.yaml": wrongKind}},
		{name: "wrong literal kind never falls back", sealing: true, arg: "secrets.yaml", files: map[string]string{"secrets.yaml": wrongKind, "secrets.unsealed.yaml": pathTestSecret}},
		{name: "wrong literal version never falls back", sealing: true, arg: "secrets.yaml", files: map[string]string{"secrets.yaml": wrongVersion, "secrets.unsealed.yaml": pathTestSecret}},
		{name: "malformed literal never falls back", sealing: true, arg: "secrets.yaml", files: map[string]string{"secrets.yaml": "metadata: [", "secrets.unsealed.yaml": pathTestSecret}},
		{name: "empty literal never falls back", sealing: true, arg: "secrets.yaml", files: map[string]string{"secrets.yaml": "", "secrets.unsealed.yaml": pathTestSecret}},
		{name: "multiple literal resources never fall back", sealing: true, arg: "secrets.yaml", files: map[string]string{"secrets.yaml": pathTestSealedSecret + "---\n" + pathTestSealedSecret, "secrets.unsealed.yaml": pathTestSecret}},
		{name: "multiple sibling resources rejected", sealing: true, arg: "secrets.yaml", files: map[string]string{"secrets.yaml": pathTestSealedSecret, "secrets.unsealed.yaml": pathTestSecret + "---\n" + pathTestSecret}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writePathTestFiles(t, dir, tt.files)
			if source, destination, err := resolveSecretPaths(filepath.Join(dir, tt.arg), "", tt.sealing); err == nil {
				t.Fatalf("unexpected success: %q -> %q", source, destination)
			}
		})
	}
}

func TestResolveSecretPathsRejectsSameFile(t *testing.T) {
	for _, sealing := range []bool{true, false} {
		name := "unseal"
		content := pathTestSealedSecret
		if sealing {
			name, content = "seal", pathTestSecret
		}
		t.Run(name, func(t *testing.T) {
			for _, alias := range []string{"same path", "hard link", "symlink"} {
				t.Run(alias, func(t *testing.T) {
					dir := t.TempDir()
					input := filepath.Join(dir, "input.yaml")
					writePathTestFiles(t, dir, map[string]string{"input.yaml": content})
					output := input
					if alias != "same path" {
						output = filepath.Join(dir, "alias.yaml")
						link := os.Link
						if alias == "symlink" {
							link = os.Symlink
						}
						if err := link(input, output); err != nil {
							t.Fatal(err)
						}
					}
					if _, _, err := resolveSecretPaths(input, output, sealing); err == nil {
						t.Fatal("source and destination refer to the same file")
					}
					data, err := os.ReadFile(input)
					if err != nil || string(data) != content {
						t.Fatalf("input changed during resolution: %v", err)
					}
				})
			}
		})
	}
}

func TestResolveSecretFilesPreflightsBatch(t *testing.T) {
	tests := []struct {
		name    string
		sealing bool
		args    []string
		output  string
		files   map[string]string
	}{
		{
			name: "duplicate outputs", args: []string{"secrets.yaml", "secrets.sealed.yaml"},
			files: map[string]string{"secrets.yaml": pathTestSealedSecret, "secrets.sealed.yaml": pathTestSealedSecret},
		},
		{
			name: "unseal output overlaps another source", args: []string{"secrets.yaml", "secrets.unsealed.yaml"},
			files: map[string]string{"secrets.yaml": pathTestSealedSecret, "secrets.unsealed.yaml": pathTestSealedSecret},
		},
		{
			name: "seal output overlaps another source", sealing: true, args: []string{"secrets.unsealed.yaml", "secrets.yaml"},
			files: map[string]string{"secrets.unsealed.yaml": pathTestSecret, "secrets.yaml": pathTestSecret},
		},
		{
			name: "explicit output with multiple inputs", args: []string{"first.yaml", "second.yaml"}, output: "custom.yaml",
			files: map[string]string{"first.yaml": pathTestSealedSecret, "second.yaml": pathTestSealedSecret},
		},
		{
			name: "later input invalid", args: []string{"first.yaml", "second.yaml"},
			files: map[string]string{"first.yaml": pathTestSealedSecret, "second.yaml": "invalid: ["},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writePathTestFiles(t, dir, tt.files)
			args := make([]string, len(tt.args))
			for i, name := range tt.args {
				args[i] = filepath.Join(dir, name)
			}
			output := ""
			if tt.output != "" {
				output = filepath.Join(dir, tt.output)
			}
			if _, err := resolveSecretFiles(args, output, tt.sealing); err == nil {
				t.Fatal("invalid batch unexpectedly resolved")
			}
			for name, original := range tt.files {
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || string(data) != original {
					t.Fatalf("file %q changed during resolution: %v", name, err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != len(tt.files) {
				t.Fatal("batch resolution created an output file")
			}
		})
	}
}

func TestResolveSecretFilesKeepsDistinctInputs(t *testing.T) {
	dir := t.TempDir()
	writePathTestFiles(t, dir, map[string]string{"first.yaml": pathTestSealedSecret, "second.yml": pathTestSealedSecret})
	args := []string{filepath.Join(dir, "first.yaml"), filepath.Join(dir, "second.yml")}
	pairs, err := resolveSecretFiles(args, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 2 {
		t.Fatalf("resolved %d inputs, want 2", len(pairs))
	}
	wantDestinations := []string{filepath.Join(dir, "first.unsealed.yaml"), filepath.Join(dir, "second.unsealed.yml")}
	for i, pair := range pairs {
		if pair.source != args[i] || pair.destination != wantDestinations[i] {
			t.Fatalf("unexpected pair %d: %#v", i, pair)
		}
	}
}

func writePathTestFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
