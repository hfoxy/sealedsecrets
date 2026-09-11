package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

func installSmartPathTestClient(t *testing.T, key *rsa.PrivateKey) {
	t.Helper()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keys, err := json.Marshal(corev1.SecretList{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "SecretList"},
		Items:    []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "test-key", Namespace: ControllerNamespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSPrivateKeyKey: privateKey}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := certificateTestTransport(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			return nil, fmt.Errorf("unexpected method: %s", req.Method)
		}
		var body []byte
		switch {
		case strings.HasSuffix(req.URL.Path, "/v1/cert.pem"):
			body = certificate
		case strings.HasSuffix(req.URL.Path, "/services/"+ControllerName):
			body = []byte(`{"apiVersion":"v1","kind":"Service","spec":{"ports":[{"name":"http","port":8080}]}}`)
		case req.URL.Path == "/api/v1/namespaces/"+ControllerNamespace+"/secrets":
			body = keys
		default:
			return nil, fmt.Errorf("unexpected request: %s", req.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})
	config := &rest.Config{Host: "https://smart-path-test.invalid", Transport: transport}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, clientConfigErr = &ClientConfig{context: "test", client: config, clientset: clientset}, nil
}

func TestSmartSealUnsealRoundTrip(t *testing.T) {
	for _, extension := range []string{".yaml", ".yml"} {
		t.Run(extension, func(t *testing.T) {
			cmd := setupUnsealTest(t)
			oldKeep, oldReseal, oldScope := KeepTemplate, Reseal, Scope
			t.Cleanup(func() { KeepTemplate, Reseal, Scope = oldKeep, oldReseal, oldScope })
			KeepTemplate, Reseal, Scope = true, false, v1alpha1.DefaultScope
			key := testSealKey(t)
			installSmartPathTestClient(t, key)
			secret := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "test"}, Data: map[string][]byte{"key": []byte("before"), "unchanged": []byte("keep")}}
			sealed, _, err := buildSealedSecret(secret, nil, nil, &key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			original, err := marshalSealedSecret(sealed, true)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			sealedPath := filepath.Join(dir, "secrets"+extension)
			plaintextPath := filepath.Join(dir, "secrets.unsealed"+extension)
			if err := os.WriteFile(sealedPath, original, 0644); err != nil {
				t.Fatal(err)
			}

			// Both commands accept the same named sealed file.
			if err := Unseal(cmd, []string{sealedPath}); err != nil {
				t.Fatal(err)
			}
			plaintext, err := os.ReadFile(plaintextPath)
			if err != nil {
				t.Fatal(err)
			}
			var editable corev1.Secret
			if err := yaml.Unmarshal(plaintext, &editable); err != nil {
				t.Fatal(err)
			}
			editable.StringData = map[string]string{"key": "after"}
			edited, err := yaml.Marshal(editable)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(plaintextPath, edited, 0600); err != nil {
				t.Fatal(err)
			}
			if err := Seal(cmd, []string{sealedPath}); err == nil || !strings.Contains(err.Error(), "--force") {
				t.Fatalf("expected overwrite protection, got %v", err)
			}
			stillOriginal, err := os.ReadFile(sealedPath)
			if err != nil || !bytes.Equal(stillOriginal, original) {
				t.Fatal("sealed destination changed without --force")
			}

			Force = true
			if err := Seal(cmd, []string{sealedPath}); err != nil {
				t.Fatal(err)
			}
			result, err := os.ReadFile(sealedPath)
			if err != nil {
				t.Fatal(err)
			}
			var updated v1alpha1.SealedSecret
			if err := yaml.UnmarshalStrict(result, &updated); err != nil {
				t.Fatal(err)
			}
			decoded, err := updated.Unseal(scheme.Codecs, map[string]*rsa.PrivateKey{"test": key})
			if err != nil {
				t.Fatal(err)
			}
			if string(decoded.Data["key"]) != "after" || string(decoded.Data["unchanged"]) != "keep" {
				t.Fatal("edited data did not round-trip")
			}
			if updated.Spec.EncryptedData["unchanged"] != sealed.Spec.EncryptedData["unchanged"] {
				t.Fatal("incremental ciphertext reuse lost")
			}
			stillEdited, err := os.ReadFile(plaintextPath)
			if err != nil || !bytes.Equal(stillEdited, edited) {
				t.Fatal("plaintext source was overwritten")
			}
			if _, err := os.Stat(sealedPath + ".yaml"); !os.IsNotExist(err) {
				t.Fatal("unexpected doubled-extension output")
			}

			// The plaintext destination can select the sealed source too.
			if err := Unseal(cmd, []string{plaintextPath}); err != nil {
				t.Fatal(err)
			}
			finalPlaintext, err := os.ReadFile(plaintextPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := yaml.Unmarshal(finalPlaintext, &editable); err != nil {
				t.Fatal(err)
			}
			if string(editable.Data["key"]) != "after" {
				t.Fatal("unseal destination selection chose the wrong source")
			}
		})
	}
}
