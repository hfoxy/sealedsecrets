package main

import (
	"context"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
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

func TestSealUpdateKeepsScopeOfSealedFile(t *testing.T) {
	for _, scope := range []v1alpha1.SealingScope{v1alpha1.NamespaceWideScope, v1alpha1.ClusterWideScope} {
		for _, reseal := range []bool{false, true} {
			t.Run(scope.String()+map[bool]string{false: "", true: "/reseal"}[reseal], func(t *testing.T) {
				// The scope annotation sits on the SealedSecret alone, as in a file
				// sealed without --keep-template.
				annotations := v1alpha1.UpdateScopeAnnotations(nil, scope)
				cmd, fixture := setupSealedUpdate(t, testUpdateSecret(annotations), false, true)
				plaintext, err := os.ReadFile(fixture.plaintext)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(plaintext), "sealedsecrets.bitnami.com/") {
					t.Fatalf("fixture should not render the scope annotation:\n%s", plaintext)
				}
				fixture.edit(t, "a", "changed")

				Force, Reseal = true, reseal
				if err := Seal(cmd, []string{fixture.sealed}); err != nil {
					t.Fatal(err)
				}
				sealed, secret := fixture.result(t)
				if got := v1alpha1.SecretScope(&sealed); got != scope {
					t.Fatalf("scope changed from %s to %s", scope.String(), got.String())
				}
				if string(secret.Data["a"]) != "changed" || string(secret.Data["b"]) != "2" {
					t.Fatalf("unexpected values: %q", secret.Data)
				}
				if !reseal && sealed.Spec.EncryptedData["b"] != fixture.original.Spec.EncryptedData["b"] {
					t.Fatal("unchanged key was encrypted again")
				}
			})
		}
	}
}

func TestSealUpdateHonoursExplicitScope(t *testing.T) {
	annotations := v1alpha1.UpdateScopeAnnotations(nil, v1alpha1.ClusterWideScope)
	_, fixture := setupSealedUpdate(t, testUpdateSecret(annotations), false, true)

	cmd, err := sealCommand(&cobra.Command{})
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetContext(context.Background())
	if err := cmd.ParseFlags([]string{"--scope", "strict"}); err != nil {
		t.Fatal(err)
	}
	Force = true
	if err := Seal(cmd, []string{fixture.sealed}); err != nil {
		t.Fatal(err)
	}
	sealed, _ := fixture.result(t)
	if got := v1alpha1.SecretScope(&sealed); got != v1alpha1.StrictScope {
		t.Fatalf("explicit strict scope ignored: %s", got.String())
	}
}

func TestUnsealOmitsOwnerReferences(t *testing.T) {
	_, fixture := setupSealedUpdate(t, testUpdateSecret(nil), false, false)
	plaintext, err := os.ReadFile(fixture.plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plaintext), "ownerReferences") {
		t.Fatalf("unsealed file holds owner references:\n%s", plaintext)
	}
}
