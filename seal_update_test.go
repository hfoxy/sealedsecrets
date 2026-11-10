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

func TestSealUpdateKeepsTemplateOfSealedFile(t *testing.T) {
	for _, reseal := range []bool{false, true} {
		t.Run(map[bool]string{false: "incremental", true: "reseal"}[reseal], func(t *testing.T) {
			secret := testUpdateSecret(map[string]string{"replicator.v1.mittwald.de/strip-labels": "true"})
			secret.Labels = map[string]string{"app": "example"}
			secret.Type = corev1.SecretTypeBasicAuth
			cmd, fixture := setupSealedUpdate(t, secret, true, false)
			fixture.edit(t, "a", "changed")

			// No --keep-template: the existing template decides.
			Force, Reseal = true, reseal
			if err := Seal(cmd, []string{fixture.sealed}); err != nil {
				t.Fatal(err)
			}
			sealed, rendered := fixture.result(t)
			if sealed.Spec.Template.Type != corev1.SecretTypeBasicAuth || sealed.Spec.Template.Namespace != "team" {
				t.Fatalf("template not kept: %#v", sealed.Spec.Template)
			}
			if rendered.Type != corev1.SecretTypeBasicAuth || rendered.Labels["app"] != "example" || rendered.Annotations["replicator.v1.mittwald.de/strip-labels"] != "true" {
				t.Fatalf("controller would render a different Secret: %#v", rendered.ObjectMeta)
			}
			if string(rendered.Data["a"]) != "changed" || string(rendered.Data["b"]) != "2" {
				t.Fatalf("unexpected values: %q", rendered.Data)
			}
		})
	}
}

func TestSealUpdateDoesNotAddTemplate(t *testing.T) {
	cmd, fixture := setupSealedUpdate(t, testUpdateSecret(nil), false, false)
	fixture.edit(t, "a", "changed")
	Force = true
	if err := Seal(cmd, []string{fixture.sealed}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture.sealed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "template:") {
		t.Fatalf("update added a template:\n%s", data)
	}
}

func TestSealUpdateLeavesSealedFileWithoutNamespace(t *testing.T) {
	for _, test := range []struct {
		name         string
		keepTemplate bool
		annotation   bool
	}{
		{"no template", false, false},
		{"template", true, false},
		{"namespace annotation", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd, fixture := setupSealedUpdate(t, testUpdateSecret(nil), test.keepTemplate, true)
			if test.annotation {
				setUnsealTestNamespace(t, fixture.sealed, "", "team")
			}
			fixture.edit(t, "a", "changed")
			Force = true
			if err := Seal(cmd, []string{fixture.sealed}); err != nil {
				t.Fatal(err)
			}
			sealed, rendered := fixture.result(t)
			if sealed.Namespace != "" || sealed.Spec.Template.Namespace != "" {
				t.Fatalf("update added a namespace: %q, template %q", sealed.Namespace, sealed.Spec.Template.Namespace)
			}
			annotation, ok := sealed.Annotations[NamespaceKey]
			if ok != test.annotation || (ok && annotation != "team") {
				t.Fatalf("namespace annotation changed: %q", sealed.Annotations)
			}
			if _, kept := sealed.Spec.Template.Annotations[NamespaceKey]; kept {
				t.Fatal("namespace annotation reached the rendered Secret")
			}
			if string(rendered.Data["a"]) != "changed" || string(rendered.Data["b"]) != "2" {
				t.Fatalf("unexpected values: %q", rendered.Data)
			}
			if sealed.Spec.EncryptedData["b"] != fixture.original.Spec.EncryptedData["b"] {
				t.Fatal("unchanged key was encrypted again")
			}
		})
	}
}

func TestSealUpdateKeepsSealedSecretMetadata(t *testing.T) {
	for _, reseal := range []bool{false, true} {
		t.Run(map[bool]string{false: "incremental", true: "reseal"}[reseal], func(t *testing.T) {
			annotations := v1alpha1.UpdateScopeAnnotations(nil, v1alpha1.ClusterWideScope)
			cmd, fixture := setupSealedUpdate(t, testUpdateSecret(annotations), false, false)
			content, err := os.ReadFile(fixture.sealed)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]interface{}
			if err := yaml.Unmarshal(content, &manifest); err != nil {
				t.Fatal(err)
			}
			metadata := manifest["metadata"].(map[string]interface{})
			metadata["labels"] = map[string]string{"app.kubernetes.io/part-of": "example"}
			metadata["annotations"].(map[string]interface{})["argocd.argoproj.io/sync-wave"] = "-10"
			if content, err = yaml.Marshal(manifest); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fixture.sealed, content, 0644); err != nil {
				t.Fatal(err)
			}
			fixture.edit(t, "a", "changed")

			Force, Reseal = true, reseal
			if err := Seal(cmd, []string{fixture.sealed}); err != nil {
				t.Fatal(err)
			}
			sealed, rendered := fixture.result(t)
			if sealed.Labels["app.kubernetes.io/part-of"] != "example" || sealed.Annotations["argocd.argoproj.io/sync-wave"] != "-10" {
				t.Fatalf("SealedSecret metadata not kept: %#v", sealed.ObjectMeta)
			}
			if v1alpha1.SecretScope(&sealed) != v1alpha1.ClusterWideScope {
				t.Fatal("scope not kept")
			}
			if string(rendered.Data["a"]) != "changed" {
				t.Fatalf("unexpected values: %q", rendered.Data)
			}
		})
	}
}

func TestSealUpdateExplicitScopeReplacesSealedScopeAnnotation(t *testing.T) {
	annotations := v1alpha1.UpdateScopeAnnotations(nil, v1alpha1.ClusterWideScope)
	_, fixture := setupSealedUpdate(t, testUpdateSecret(annotations), false, false)
	cmd, err := sealCommand(&cobra.Command{})
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetContext(context.Background())
	if err := cmd.ParseFlags([]string{"--scope", "namespace-wide", "--reseal"}); err != nil {
		t.Fatal(err)
	}
	Force = true
	if err := Seal(cmd, []string{fixture.sealed}); err != nil {
		t.Fatal(err)
	}
	sealed, _ := fixture.result(t)
	if _, ok := sealed.Annotations[v1alpha1.SealedSecretClusterWideAnnotation]; ok {
		t.Fatalf("old scope annotation kept beside the new one: %q", sealed.Annotations)
	}
	if v1alpha1.SecretScope(&sealed) != v1alpha1.NamespaceWideScope {
		t.Fatal("explicit scope ignored")
	}
}
