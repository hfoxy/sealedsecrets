package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	sealedcrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

type unsealTestTransport func(*http.Request) (*http.Response, error)

func (f unsealTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func setupUnsealTest(t *testing.T) *cobra.Command {
	t.Helper()
	oldClient, oldClientErr := clientConfig, clientConfigErr
	oldNamespace, oldOutput, oldDecode, oldForce := Namespace, OutputFile, Decode, Force
	t.Cleanup(func() {
		clientConfig, clientConfigErr = oldClient, oldClientErr
		Namespace, OutputFile, Decode, Force = oldNamespace, oldOutput, oldDecode, oldForce
	})
	// An unexpected client lookup must fail without consulting the local kubeconfig.
	clientConfig, clientConfigErr = nil, errors.New("unexpected kubernetes client lookup")
	Namespace, OutputFile, Decode, Force = "", "", false, false
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	return cmd
}

func unsealTestInput(t *testing.T, data map[string][]byte) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keys, err := json.Marshal(corev1.SecretList{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "SecretList"},
		Items: []corev1.Secret{{
			ObjectMeta: metav1.ObjectMeta{Name: "test-sealing-key", Namespace: ControllerNamespace},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSPrivateKeyKey: privateKey},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientset, err := kubernetes.NewForConfig(&rest.Config{
		Host: "https://unseal-test.invalid",
		Transport: unsealTestTransport(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/"+ControllerNamespace+"/secrets" {
				t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				return nil, errors.New("unexpected request")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(keys))}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, clientConfigErr = &ClientConfig{context: "test", clientset: clientset}, nil

	encrypted := make(map[string]string)
	for name, value := range data {
		ciphertext, err := sealedcrypto.HybridEncrypt(rand.Reader, &key.PublicKey, value, []byte("test-ns/test-secret"))
		if err != nil {
			t.Fatal(err)
		}
		encrypted[name] = base64.StdEncoding.EncodeToString(ciphertext)
	}
	manifest, err := yaml.Marshal(map[string]interface{}{
		"apiVersion": "bitnami.com/v1alpha1",
		"kind":       "SealedSecret",
		"metadata":   map[string]string{"name": "test-secret", "namespace": "test-ns"},
		"spec": map[string]interface{}{
			"encryptedData": encrypted,
			"template": map[string]interface{}{
				"metadata": map[string]string{"name": "test-secret", "namespace": "test-ns"},
				"type":     "Opaque",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "secret.yaml")
	if err := os.WriteFile(input, manifest, 0600); err != nil {
		t.Fatal(err)
	}
	return input
}

func TestUnsealDecodePreservesBinaryData(t *testing.T) {
	cmd := setupUnsealTest(t)
	binary := []byte{0x00, 0xff, 0xc0, 0x80, 0x42}
	input := unsealTestInput(t, map[string][]byte{
		"binary": binary,
		"text":   []byte("hello\nworld"),
		"empty":  {},
	})
	Decode = true
	output := filepath.Join(t.TempDir(), "unsealed.yaml")
	if err := unseal(cmd, input, output); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var secret corev1.Secret
	if err := yaml.Unmarshal(content, &secret); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret.Data["binary"], binary) {
		t.Fatalf("binary data changed: got %x, want %x", secret.Data["binary"], binary)
	}
	if _, exists := secret.StringData["binary"]; exists {
		t.Fatal("binary data must remain in data")
	}
	if secret.StringData["text"] != "hello\nworld" {
		t.Fatalf("decoded text changed: %q", secret.StringData["text"])
	}
	if value, exists := secret.StringData["empty"]; !exists || value != "" {
		t.Fatalf("empty value lost: value %q, exists %v", value, exists)
	}
	if len(secret.Data) != 1 {
		t.Fatalf("expected only binary data to remain encoded, got %v", secret.Data)
	}
	if secret.Namespace != "test-ns" {
		t.Fatalf("namespace changed: %q", secret.Namespace)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("plaintext output permissions: %o", info.Mode().Perm())
	}
}

func TestUnsealRejectsOverwriteWithoutForce(t *testing.T) {
	cmd := setupUnsealTest(t)
	OutputFile = filepath.Join(t.TempDir(), "output.yaml")
	if err := os.WriteFile(OutputFile, []byte("existing content"), 0600); err != nil {
		t.Fatal(err)
	}
	err := Unseal(cmd, []string{"input-should-not-be-read.yaml"})
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("expected overwrite error, got %v", err)
	}
	content, err := os.ReadFile(OutputFile)
	if err != nil || string(content) != "existing content" {
		t.Fatalf("existing output changed: %q, %v", content, err)
	}
}

func TestUnsealReportsInputErrors(t *testing.T) {
	for _, test := range []struct {
		name     string
		manifest string
		want     string
	}{
		{"missing file", "", "unable to read file"},
		{"invalid yaml", "[", "unable to unmarshal"},
		{"wrong kind", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  namespace: test\n", "must contain"},
		{"multiple documents", "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  namespace: test\n---\napiVersion: v1\nkind: Secret\n", "unable to unmarshal"},
		{"missing namespace", "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: test\n", "unable to determine namespace"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := setupUnsealTest(t)
			input := filepath.Join(t.TempDir(), "input.yaml")
			if test.manifest != "" {
				if err := os.WriteFile(input, []byte(test.manifest), 0600); err != nil {
					t.Fatal(err)
				}
			}
			OutputFile = filepath.Join(t.TempDir(), "output.yaml")
			if err := Unseal(cmd, []string{input}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q error, got %v", test.want, err)
			}
			if _, err := os.Stat(OutputFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed unseal created an output: %v", err)
			}
		})
	}
}

func TestWriteUnsealedFileHonorsForceAndRestrictsPermissions(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output.yaml")
	if err := os.WriteFile(output, []byte("old content is longer"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeUnsealedFile(output, []byte("new"), false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected existing-file error, got %v", err)
	}
	if err := writeUnsealedFile(output, []byte("new"), true); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(output)
	if err != nil || string(content) != "new" {
		t.Fatalf("force did not replace output: %q, %v", content, err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("plaintext output permissions: %o", info.Mode().Perm())
	}
}

func TestUnsealForUpdateUsesOriginalNamespace(t *testing.T) {
	for _, test := range []struct {
		name         string
		manifestNS   string
		annotationNS string
		commandNS    string
	}{
		{"manifest namespace before command", "test-ns", "", "new"},
		{"manifest namespace before annotation", "test-ns", "stale", "new"},
		{"annotation before command", "", "test-ns", "new"},
		{"command fallback", "", "", "test-ns"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := setupUnsealTest(t)
			input := unsealTestInput(t, map[string][]byte{"text": []byte("original value")})
			setUnsealTestNamespace(t, input, test.manifestNS, test.annotationNS)
			Namespace = test.commandNS

			out, original, err := unsealSecretForUpdate(cmd, input)
			if err != nil {
				t.Fatal(err)
			}
			var secret corev1.Secret
			if err := yaml.Unmarshal([]byte(out), &secret); err != nil {
				t.Fatal(err)
			}
			if string(secret.Data["text"]) != "original value" || original.Namespace != "test-ns" {
				t.Fatal("update did not decrypt with the original namespace")
			}
			if Namespace != test.commandNS {
				t.Fatal("update changed the namespace selected for the destination")
			}
		})
	}
}

func TestUnsealHonorsExplicitNamespaceOverride(t *testing.T) {
	cmd := setupUnsealTest(t)
	input := unsealTestInput(t, map[string][]byte{"text": []byte("original value")})
	Namespace = "new"
	if _, _, err := unsealSecret(cmd, input); err == nil {
		t.Fatal("ordinary unseal ignored the explicit namespace override")
	}

	// The override must also allow decryption when the manifest metadata has
	// been set to a namespace other than the one used for encryption.
	setUnsealTestNamespace(t, input, "new", "")
	Namespace = "test-ns"
	if _, original, err := unsealSecret(cmd, input); err != nil {
		t.Fatal(err)
	} else if original.Namespace != "test-ns" {
		t.Fatal("ordinary unseal did not apply the explicit namespace")
	}
}

func setUnsealTestNamespace(t *testing.T, input, namespace, annotation string) {
	t.Helper()
	content, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]interface{}
	if err := yaml.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	metadata := manifest["metadata"].(map[string]interface{})
	if namespace == "" {
		delete(metadata, "namespace")
	} else {
		metadata["namespace"] = namespace
	}
	if annotation != "" {
		metadata["annotations"] = map[string]string{NamespaceKey: annotation}
	}
	content, err = yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, content, 0600); err != nil {
		t.Fatal(err)
	}
}
