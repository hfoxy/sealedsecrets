package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
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

func TestNewKubeClientPreservesConfigListPrecedence(t *testing.T) {
	firstDir, secondDir := t.TempDir(), t.TempDir()
	first := writeKubeTestConfig(t, filepath.Join(firstDir, "config"), "context", "https://first.invalid", `extensions:
- name: fixture
  extension:
    source: first
`)
	second := writeKubeTestConfig(t, filepath.Join(secondDir, "config"), "alternate", "https://second.invalid", `extensions:
- name: fixture
  extension:
    source: second
`)
	secondConfig, err := clientcmd.LoadFromFile(second)
	if err != nil {
		t.Fatal(err)
	}
	secondConfig.AuthInfos["user"].Token = ""
	secondConfig.AuthInfos["user"].TokenFile = "token"
	secondConfig.Contexts["context"].Namespace = "second"
	secondConfig.Contexts["alternate"] = &clientcmdapi.Context{Cluster: "cluster", AuthInfo: "user", Namespace: "alternate"}
	if err := clientcmd.WriteToFile(*secondConfig, second); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secondDir, "token"), []byte("second-token"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, override := range []string{"", "alternate"} {
		t.Run("context="+override, func(t *testing.T) {
			// Empty and missing entries have the same behavior as client-go lists.
			pathList := strings.Join([]string{first, "", filepath.Join(t.TempDir(), "missing"), second}, string(os.PathListSeparator))
			setKubeTestFlags(t, pathList, override)
			client, err := newKubeClient()
			if err != nil {
				t.Fatal(err)
			}
			if client.client.Host != "https://second.invalid" {
				t.Fatalf("server = %q, want later cluster definition", client.client.Host)
			}
			if client.client.BearerToken != "second-token" || client.client.BearerTokenFile != filepath.Join(secondDir, "token") {
				t.Fatal("later user definition or relative credential path was lost")
			}
			if client.config.Contexts["context"].Namespace != "second" {
				t.Fatal("later named context definition was lost")
			}
			extension, ok := client.config.Extensions["fixture"].(*runtime.Unknown)
			if !ok || !bytes.Contains(extension.Raw, []byte("second")) {
				t.Fatal("later extension definition was lost")
			}
			wantContext, wantNamespace := "context", "second"
			if override != "" {
				wantContext, wantNamespace = "alternate", "alternate"
			}
			if client.context != wantContext {
				t.Fatalf("current context = %q, want %q", client.context, wantContext)
			}
			namespace, _, err := client.Namespace()
			if err != nil || namespace != wantNamespace {
				t.Fatalf("namespace = %q, %v; want %q", namespace, err, wantNamespace)
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
