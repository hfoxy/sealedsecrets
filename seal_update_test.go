package main

import (
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"
)

// sealedUpdateFixture is a sealed file, as a repository holds it, beside the
// unsealed file the CLI writes for it.
type sealedUpdateFixture struct {
	key       *rsa.PrivateKey
	sealed    string
	plaintext string
	original  v1alpha1.SealedSecret
}

func setupSealedUpdate(t *testing.T, secret *corev1.Secret, keepTemplate, withoutNamespace bool) (*cobra.Command, *sealedUpdateFixture) {
	t.Helper()
	cmd := setupUnsealTest(t)
	oldKeep, oldReseal, oldScope := KeepTemplate, Reseal, Scope
	t.Cleanup(func() { KeepTemplate, Reseal, Scope = oldKeep, oldReseal, oldScope })
	KeepTemplate, Reseal, Scope = false, false, v1alpha1.DefaultScope
	key := testSealKey(t)
	installSmartPathTestClient(t, key)

	sealed, _, err := buildSealedSecret(secret, nil, nil, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if withoutNamespace {
		sealed.Namespace = ""
		sealed.Spec.Template.Namespace = ""
	}
	data, err := marshalSealedSecret(sealed, keepTemplate)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fixture := &sealedUpdateFixture{key: key, sealed: filepath.Join(dir, "secrets.yaml"), plaintext: filepath.Join(dir, "secrets.unsealed.yaml")}
	if err := os.WriteFile(fixture.sealed, data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &fixture.original); err != nil {
		t.Fatal(err)
	}

	// Unseal as a user does, naming the namespace a namespace-less file needs.
	Namespace = secret.Namespace
	if err := Unseal(cmd, []string{fixture.sealed}); err != nil {
		t.Fatal(err)
	}
	Namespace = ""
	return cmd, fixture
}

func (f *sealedUpdateFixture) edit(t *testing.T, key, value string) {
	t.Helper()
	data, err := os.ReadFile(f.plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var secret corev1.Secret
	if err := yaml.Unmarshal(data, &secret); err != nil {
		t.Fatal(err)
	}
	secret.StringData = map[string]string{key: value}
	data, err = yaml.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.plaintext, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *sealedUpdateFixture) result(t *testing.T) (v1alpha1.SealedSecret, *corev1.Secret) {
	t.Helper()
	data, err := os.ReadFile(f.sealed)
	if err != nil {
		t.Fatal(err)
	}
	var sealed v1alpha1.SealedSecret
	if err := yaml.UnmarshalStrict(data, &sealed); err != nil {
		t.Fatalf("invalid sealed secret: %v\n%s", err, data)
	}
	// Decrypt as the controller would, with the namespace kustomize assigns.
	deployed := sealed.DeepCopy()
	if deployed.Namespace == "" {
		deployed.Namespace = "team"
	}
	secret, err := deployed.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"test": f.key})
	if err != nil {
		t.Fatalf("controller could not decrypt the updated file: %v\n%s", err, data)
	}
	return sealed, secret
}

func testUpdateSecret(annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team", Annotations: annotations},
		Data:       map[string][]byte{"a": []byte("1"), "b": []byte("2")},
	}
}

func TestSealUpdatesSealedFileWithoutNamespace(t *testing.T) {
	cmd, fixture := setupSealedUpdate(t, testUpdateSecret(nil), false, true)
	fixture.edit(t, "a", "changed")

	// The unsealed file names the namespace, so the update needs no --namespace.
	Force = true
	if err := Seal(cmd, []string{fixture.sealed}); err != nil {
		t.Fatal(err)
	}
	sealed, secret := fixture.result(t)
	if string(secret.Data["a"]) != "changed" || string(secret.Data["b"]) != "2" {
		t.Fatalf("unexpected values: %q", secret.Data)
	}
	if sealed.Spec.EncryptedData["b"] != fixture.original.Spec.EncryptedData["b"] {
		t.Fatal("unchanged key was encrypted again")
	}
}
