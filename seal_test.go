package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

func TestMarshalSealedSecretTemplate(t *testing.T) {
	immutable := true
	templateText := "header\n  creationTimestamp: null\nfooter\n"
	secret := &v1alpha1.SealedSecret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "bitnami.com/v1alpha1", Kind: "SealedSecret"},
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "test"},
		Spec: v1alpha1.SealedSecretSpec{
			EncryptedData: map[string]string{"password": "synthetic-ciphertext"},
			Template: v1alpha1.SecretTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "test", Labels: map[string]string{"app": "example"}},
				Type:       corev1.SecretTypeOpaque,
				Immutable:  &immutable,
				Data:       map[string]*string{"config": &templateText, "password": nil},
			},
		},
	}
	for _, keep := range []bool{true, false} {
		t.Run(map[bool]string{true: "keep", false: "omit"}[keep], func(t *testing.T) {
			data, err := marshalSealedSecret(secret, keep)
			if err != nil {
				t.Fatal(err)
			}
			var restored v1alpha1.SealedSecret
			if err := yaml.UnmarshalStrict(data, &restored); err != nil {
				t.Fatalf("output is invalid YAML: %v\n%s", err, data)
			}
			var document map[string]interface{}
			if err := yaml.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			if _, exists := document["metadata"].(map[string]interface{})["creationTimestamp"]; exists {
				t.Fatal("top-level timestamp was retained")
			}
			spec := document["spec"].(map[string]interface{})
			if _, exists := spec["template"]; exists != keep {
				t.Fatalf("template presence = %v, want %v", exists, keep)
			}
			if keep {
				metadata := spec["template"].(map[string]interface{})["metadata"].(map[string]interface{})
				if _, exists := metadata["creationTimestamp"]; exists {
					t.Fatal("template timestamp retained")
				}
				if !reflect.DeepEqual(restored.Spec.Template, secret.Spec.Template) {
					t.Fatalf("template did not round-trip: %#v", restored.Spec.Template)
				}
				if !bytes.Contains(data, []byte("  template:\n")) || !bytes.Contains(data, []byte("      name: example\n")) {
					t.Fatalf("unexpected template indentation:\n%s", data)
				}
			}
		})
	}
}

func testSealKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestIncrementalSealPreservesDataAndStringDataPrecedence(t *testing.T) {
	key := testSealKey(t)
	original := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "test"},
		Data:       map[string][]byte{"retained": []byte("keep"), "changed": []byte("old"), "unchanged": []byte("same"), "empty": {}},
	}
	previous, err := v1alpha1.NewSealedSecret(scheme.Codecs, &key.PublicKey, original)
	if err != nil {
		t.Fatal(err)
	}
	source := original.DeepCopy()
	source.Data = map[string][]byte{"changed": []byte("old"), "unchanged": []byte("same")}
	source.StringData = map[string]string{"changed": "new", "added": "value"}
	sealed, skipped, err := buildSealedSecret(source, original, previous, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(skipped, []string{"empty", "retained", "unchanged"}) {
		t.Fatalf("skipped = %v", skipped)
	}
	for _, name := range skipped {
		if sealed.Spec.EncryptedData[name] != previous.Spec.EncryptedData[name] {
			t.Errorf("ciphertext changed for %s", name)
		}
	}
	unsealed, err := sealed.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"test": key})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{"retained": []byte("keep"), "changed": []byte("new"), "unchanged": []byte("same"), "empty": {}, "added": []byte("value")}
	if len(unsealed.Data) != len(want) {
		t.Fatalf("unexpected number of unsealed keys: %d", len(unsealed.Data))
	}
	for name, value := range want {
		actual, exists := unsealed.Data[name]
		if !exists || !bytes.Equal(actual, value) {
			t.Errorf("unexpected value for %s: %q", name, actual)
		}
	}
	if source.StringData["changed"] != "new" || len(source.Data) != 2 {
		t.Fatal("input mutated")
	}
}

func TestIncrementalSealAppliesMetadataOnlyChanges(t *testing.T) {
	key := testSealKey(t)
	original := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "test"}, Data: map[string][]byte{"key": []byte("value")}}
	previous, err := v1alpha1.NewSealedSecret(scheme.Codecs, &key.PublicKey, original)
	if err != nil {
		t.Fatal(err)
	}
	source := original.DeepCopy()
	source.Labels = map[string]string{"version": "updated"}
	source.Type = corev1.SecretTypeOpaque
	sealed, skipped, err := buildSealedSecret(source, original, previous, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 1 || sealed.Spec.EncryptedData["key"] != previous.Spec.EncryptedData["key"] {
		t.Fatal("unchanged key was re-encrypted")
	}
	if sealed.Spec.Template.Labels["version"] != "updated" || sealed.Spec.Template.Type != source.Type {
		t.Fatal("metadata-only changes lost")
	}
}

func TestIncrementalSealReencryptsWhenEncryptionLabelChanges(t *testing.T) {
	key := testSealKey(t)
	original := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "test"}, Data: map[string][]byte{"key": []byte("value")}}
	previous, err := v1alpha1.NewSealedSecret(scheme.Codecs, &key.PublicKey, original)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"name", "namespace", "scope"} {
		t.Run(change, func(t *testing.T) {
			source := original.DeepCopy()
			switch change {
			case "name":
				source.Name = "renamed"
			case "namespace":
				source.Namespace = "other"
			case "scope":
				source.Annotations = v1alpha1.UpdateScopeAnnotations(nil, v1alpha1.ClusterWideScope)
			}
			sealed, skipped, err := buildSealedSecret(source, original, previous, &key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if len(skipped) != 0 || sealed.Spec.EncryptedData["key"] == previous.Spec.EncryptedData["key"] {
				t.Fatal("ciphertext reused with a different encryption label")
			}
			unsealed, err := sealed.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"test": key})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(unsealed.Data["key"], original.Data["key"]) {
				t.Fatal("plaintext changed")
			}
		})
	}
}

func TestSealKeepTemplateWithNamespaceFlagAndStrictScope(t *testing.T) {
	setupUnsealTest(t)
	oldKeep, oldReseal, oldScope := KeepTemplate, Reseal, Scope
	t.Cleanup(func() { KeepTemplate, Reseal, Scope = oldKeep, oldReseal, oldScope })
	KeepTemplate, Reseal, Scope = true, true, v1alpha1.DefaultScope
	Namespace = "target"
	key := testSealKey(t)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	transport := certificateTestTransport(func(req *http.Request) (*http.Response, error) {
		body := []byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"sealed-secrets-controller","namespace":"kube-system"},"spec":{"ports":[{"name":"http","port":8080}]}}`)
		if strings.HasSuffix(req.URL.Path, "/v1/cert.pem") {
			body = certificate
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})
	config := &rest.Config{Host: "https://seal-test.invalid", Transport: transport}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, clientConfigErr = &ClientConfig{client: config, clientset: clientset}, nil
	input := filepath.Join(t.TempDir(), "secret.unsealed.yaml")
	manifest := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: example\n  annotations:\n    sealedsecrets.bitnami.com/cluster-wide: 'true'\n  labels:\n    app: example\ntype: Opaque\nstringData:\n  key: value\n"
	if err := os.WriteFile(input, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	cmd, err := sealCommand(&cobra.Command{})
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetContext(context.Background())
	if err := cmd.ParseFlags([]string{"--scope", "strict"}); err != nil {
		t.Fatal(err)
	}
	OutputFile = filepath.Join(t.TempDir(), "sealed.yaml")
	if err := Seal(cmd, []string{input}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(OutputFile)
	if err != nil {
		t.Fatal(err)
	}
	var sealed v1alpha1.SealedSecret
	if err := yaml.UnmarshalStrict(data, &sealed); err != nil {
		t.Fatalf("invalid template YAML: %v\n%s", err, data)
	}
	if sealed.Spec.Template.Name != "example" || sealed.Spec.Template.Namespace != "target" || sealed.Spec.Template.Labels["app"] != "example" {
		t.Fatalf("invalid template metadata: %#v", sealed.Spec.Template)
	}
	if v1alpha1.SecretScope(&sealed) != v1alpha1.StrictScope {
		t.Fatal("explicit strict scope ignored")
	}
	if sealed.Annotations[NamespaceKey] != "target" {
		t.Fatal("namespace annotation missing")
	}
	unsealed, err := sealed.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"test": key})
	if err != nil {
		t.Fatal(err)
	}
	if string(unsealed.Data["key"]) != "value" {
		t.Fatal("secret did not round-trip")
	}
}

func TestSealReportsFailures(t *testing.T) {
	cmd := setupUnsealTest(t)
	OutputFile = filepath.Join(t.TempDir(), "sealed.yaml")
	if err := Seal(cmd, []string{"missing-input.yaml"}); err == nil {
		t.Fatal("input error reported as success")
	}
	if err := os.WriteFile(OutputFile, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Seal(cmd, []string{"missing-input.yaml"}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("expected overwrite error, got %v", err)
	}
}

func TestIncrementalSealPreservesRenderedTemplateOutput(t *testing.T) {
	key := testSealKey(t)
	raw := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "test"}, Data: map[string][]byte{"key": []byte("raw")}}
	previous, err := v1alpha1.NewSealedSecret(scheme.Codecs, &key.PublicKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	templateText := "rendered-{{ .key }}"
	previous.Spec.Template.Data = map[string]*string{"rendered": &templateText}
	original, err := previous.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"test": key})
	if err != nil {
		t.Fatal(err)
	}
	source := original.DeepCopy()
	source.TypeMeta = raw.TypeMeta
	sealed, skipped, err := buildSealedSecret(source, original, previous, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(skipped, []string{"key"}) {
		t.Fatalf("skipped = %v, want only original encrypted key", skipped)
	}
	unsealed, err := sealed.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"test": key})
	if err != nil {
		t.Fatal(err)
	}
	if string(unsealed.Data["key"]) != "raw" || string(unsealed.Data["rendered"]) != "rendered-raw" {
		t.Fatalf("template result changed: %#v", unsealed.Data)
	}
}

func TestSealedSecretNullableTemplateData(t *testing.T) {
	key := testSealKey(t)
	source := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "test"},
		Data:       map[string][]byte{"hidden": []byte("private"), "collision": []byte("encrypted-value")},
	}
	sealed, _, err := buildSealedSecret(source, nil, nil, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	derived, collision := "derived-{{ .hidden }}", "template-value"
	sealed.Spec.Template.Data = map[string]*string{"hidden": nil, "derived": &derived, "collision": &collision}
	data, err := marshalSealedSecret(sealed, true)
	if err != nil {
		t.Fatal(err)
	}
	var restored v1alpha1.SealedSecret
	if err := yaml.UnmarshalStrict(data, &restored); err != nil {
		t.Fatal(err)
	}
	if value, exists := restored.Spec.Template.Data["hidden"]; !exists || value != nil {
		t.Fatal("null template key did not survive formatting")
	}
	unsealed, err := restored.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"test": key})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := unsealed.Data["hidden"]; exists {
		t.Fatal("null template key did not omit encrypted value from output")
	}
	if string(unsealed.Data["derived"]) != "derived-private" {
		t.Fatal("template could not reference the omitted encrypted value")
	}
	if string(unsealed.Data["collision"]) != "encrypted-value" {
		t.Fatal("template incorrectly replaced an encrypted value")
	}
}

func TestSealDoesNotOverwriteDanglingSymlinkWithoutForce(t *testing.T) {
	cmd := setupUnsealTest(t)
	dir := t.TempDir()
	OutputFile = filepath.Join(dir, "output.yaml")
	target := filepath.Join(dir, "missing.yaml")
	if err := os.Symlink(target, OutputFile); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := Seal(cmd, []string{"missing-input.yaml"}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("expected overwrite error, got %v", err)
	}
	if err := writeSealedFile(OutputFile, []byte("content"), false); err == nil {
		t.Fatal("write through symlink succeeded without force")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("symlink target was created: %v", err)
	}
}
