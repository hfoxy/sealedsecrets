package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKubeTestConfig(t *testing.T, filename, currentContext, server, extra string) string {
	t.Helper()
	data := `apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: ` + server + `
    insecure-skip-tls-verify: true
users:
- name: user
  user:
    token: synthetic-token
contexts:
- name: context
  context:
    cluster: cluster
    user: user
    namespace: fixture
current-context: ` + currentContext + "\n" + extra
	if err := os.WriteFile(filename, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return filename
}

func setKubeTestFlags(t *testing.T, path, contextName string) {
	t.Helper()
	oldKubeConfig, oldContext := KubeConfig, Context
	KubeConfig, Context = path, contextName
	t.Cleanup(func() {
		KubeConfig, Context = oldKubeConfig, oldContext
	})
}

func TestNewKubeClientResolvesRelativeCredentialPaths(t *testing.T) {
	dir := t.TempDir()
	filename := writeKubeTestConfig(t, filepath.Join(dir, "config"), "context", "https://example.invalid", "")
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte("token: synthetic-token"), []byte("tokenFile: token"))
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("synthetic-token"), 0600); err != nil {
		t.Fatal(err)
	}
	setKubeTestFlags(t, filename, "")
	client, err := newKubeClient()
	if err != nil {
		t.Fatal(err)
	}
	if client.client.BearerTokenFile != filepath.Join(dir, "token") {
		t.Fatalf("token path = %q, want resolved path", client.client.BearerTokenFile)
	}
	if client.client.BearerToken != "synthetic-token" {
		t.Fatalf("relative token file was not loaded")
	}
}

func TestNewKubeClientLoadsExtensions(t *testing.T) {
	filename := writeKubeTestConfig(t, filepath.Join(t.TempDir(), "config"), "context", "https://example.invalid", `extensions:
- name: fixture
  extension:
    enabled: true
`)
	setKubeTestFlags(t, filename, "")
	client, err := newKubeClient()
	if err != nil {
		t.Fatal(err)
	}
	if client.config.Extensions["fixture"] == nil {
		t.Fatal("kubeconfig extension was lost")
	}
}

func TestNewKubeClientMergesConfigLists(t *testing.T) {
	for _, separator := range []string{";", string(os.PathListSeparator)} {
		t.Run(separator, func(t *testing.T) {
			dir := t.TempDir()
			first := writeKubeTestConfig(t, filepath.Join(dir, "first"), "context", "https://first.invalid", "")
			second := writeKubeTestConfig(t, filepath.Join(dir, "second"), "", "https://second.invalid", "")
			setKubeTestFlags(t, first+separator+second, "")
			client, err := newKubeClient()
			if err != nil {
				t.Fatal(err)
			}
			if client.client.Host != "https://second.invalid" {
				t.Fatalf("server = %q, want existing last-file precedence", client.client.Host)
			}
			if client.context != "context" {
				t.Fatalf("current context = %q, want context", client.context)
			}
		})
	}
}

func TestNewKubeClientDoesNotLogCredentialsOnInvalidConfig(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(filename, []byte("token: synthetic-private-token\ninvalid: [\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setKubeTestFlags(t, filename, "")
	var output bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(oldOutput) })
	_, err := newKubeClient()
	if err == nil {
		t.Fatal("expected malformed kubeconfig to fail")
	}
	if strings.Contains(output.String(), "synthetic-private-token") {
		t.Fatal("malformed kubeconfig logged credentials")
	}
}

func TestNewKubeClientRejectsMissingExplicitFile(t *testing.T) {
	setKubeTestFlags(t, filepath.Join(t.TempDir(), "missing"), "")
	if _, err := newKubeClient(); err == nil {
		t.Fatal("expected missing kubeconfig to fail")
	}
}
