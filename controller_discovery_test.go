package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func setupControllerDiscoveryTest(t *testing.T, namespace, name string, handler func(*http.Request) (*http.Response, error)) {
	t.Helper()
	oldNamespace, oldName := ControllerNamespace, ControllerName
	oldClient, oldErr := clientConfig, clientConfigErr
	t.Cleanup(func() {
		ControllerNamespace, ControllerName = oldNamespace, oldName
		clientConfig, clientConfigErr = oldClient, oldErr
	})
	ControllerNamespace, ControllerName = namespace, name
	config := &rest.Config{Host: "https://controller-discovery.invalid", Transport: certificateTestTransport(handler)}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, clientConfigErr = &ClientConfig{context: "synthetic", client: config, clientset: clientset}, nil
}

func controllerDiscoveryJSON(t *testing.T, code int, object interface{}) *http.Response {
	t.Helper()
	if code != http.StatusOK {
		reason := map[int]metav1.StatusReason{
			http.StatusNotFound:     metav1.StatusReasonNotFound,
			http.StatusForbidden:    metav1.StatusReasonForbidden,
			http.StatusUnauthorized: metav1.StatusReasonUnauthorized,
		}[code]
		object = &metav1.Status{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
			Status:   metav1.StatusFailure,
			Reason:   reason,
			Code:     int32(code),
			Message:  "synthetic " + http.StatusText(code),
		}
	}
	body, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}
}

func controllerDiscoveryKeys(namespace string, count int) *corev1.SecretList {
	list := &corev1.SecretList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "SecretList"}}
	for i := 0; i < count; i++ {
		list.Items = append(list.Items, corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("key-%d", i), Namespace: namespace},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSPrivateKeyKey: []byte("synthetic-key")},
		})
	}
	return list
}

func TestPrivateKeyControllerDiscovery(t *testing.T) {
	cases := []struct {
		name                string
		namespace           string
		initialStatus       int
		initialKeys         int
		discover            bool
		discoveryStatus     int
		discoveryNamespaces []string
		wantKeys            int
	}{
		{name: "legacy default", initialStatus: http.StatusOK, initialKeys: 1, wantKeys: 1},
		{name: "empty default", initialStatus: http.StatusOK, discover: true, discoveryStatus: http.StatusOK, discoveryNamespaces: []string{"sealed-secrets"}, wantKeys: 1},
		{name: "missing default", initialStatus: http.StatusNotFound, discover: true, discoveryStatus: http.StatusOK, discoveryNamespaces: []string{"sealed-secrets"}, wantKeys: 1},
		{name: "forbidden default", initialStatus: http.StatusForbidden, discover: true, discoveryStatus: http.StatusOK, discoveryNamespaces: []string{"sealed-secrets"}, wantKeys: 1},
		{name: "rotated keys in one namespace", initialStatus: http.StatusOK, discover: true, discoveryStatus: http.StatusOK, discoveryNamespaces: []string{"sealed-secrets", "sealed-secrets"}, wantKeys: 2},
		{name: "explicit namespace", namespace: "custom", initialStatus: http.StatusOK, initialKeys: 1, wantKeys: 1},
		{name: "explicit empty namespace", namespace: "custom", initialStatus: http.StatusOK},
		{name: "explicit forbidden namespace", namespace: "custom", initialStatus: http.StatusForbidden},
		{name: "expired authentication", initialStatus: http.StatusUnauthorized},
		{name: "ambiguous namespaces", initialStatus: http.StatusOK, discover: true, discoveryStatus: http.StatusOK, discoveryNamespaces: []string{"controller-a", "controller-b"}},
		{name: "no keys anywhere", initialStatus: http.StatusOK, discover: true, discoveryStatus: http.StatusOK},
		{name: "discovery forbidden", initialStatus: http.StatusOK, discover: true, discoveryStatus: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			initialNamespace := tc.namespace
			if initialNamespace == "" {
				initialNamespace = "kube-system"
			}
			discovered := false
			setupControllerDiscoveryTest(t, tc.namespace, "", func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || req.URL.Query().Get("labelSelector") != "sealedsecrets.bitnami.com/sealed-secrets-key=active" {
					t.Errorf("unexpected key request: %s %s", req.Method, req.URL)
					return nil, errors.New("unexpected key request")
				}
				switch req.URL.Path {
				case "/api/v1/namespaces/" + initialNamespace + "/secrets":
					return controllerDiscoveryJSON(t, tc.initialStatus, controllerDiscoveryKeys(initialNamespace, tc.initialKeys)), nil
				case "/api/v1/secrets":
					if !tc.discover {
						t.Error("discovery ignored the explicit namespace or authentication failure")
						return nil, errors.New("unexpected discovery")
					}
					discovered = true
					if !strings.Contains(req.Header.Get("Accept"), "PartialObjectMetadata") {
						t.Error("cluster-wide key discovery requested private key payloads")
					}
					metadata := &metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}}
					for i, namespace := range tc.discoveryNamespaces {
						metadata.Items = append(metadata.Items, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("key-%d", i), Namespace: namespace}})
					}
					return controllerDiscoveryJSON(t, tc.discoveryStatus, metadata), nil
				case "/api/v1/namespaces/sealed-secrets/secrets":
					if !discovered || tc.wantKeys == 0 {
						t.Error("retrieved key payloads without a unique discovered namespace")
						return nil, errors.New("unexpected private key retrieval")
					}
					return controllerDiscoveryJSON(t, http.StatusOK, controllerDiscoveryKeys("sealed-secrets", tc.wantKeys)), nil
				default:
					t.Errorf("unexpected request: %s", req.URL)
					return nil, errors.New("unexpected request")
				}
			})
			result, err := getPrivateKey(context.Background())
			if tc.wantKeys == 0 {
				if err == nil || result != "" {
					t.Fatalf("expected discovery failure, got output and error %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			} else if strings.Count(result, "kind: Secret\n") != tc.wantKeys {
				t.Fatalf("wrong number of exported sealing keys, want %d", tc.wantKeys)
			}
			if discovered != tc.discover {
				t.Fatalf("discovery performed = %v, want %v", discovered, tc.discover)
			}
		})
	}
}

func controllerDiscoveryService(namespace, name, component, portName string) corev1.Service {
	service := corev1.Service{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{
			"app.kubernetes.io/name": "sealed-secrets", "app.kubernetes.io/component": component,
		}},
	}
	if portName != "" {
		service.Spec.Ports = []corev1.ServicePort{{Name: portName, Port: 8080}}
	}
	return service
}

func controllerDiscoveryCertificate(t *testing.T) (*rsa.PublicKey, []byte) {
	t.Helper()
	key := testSealKey(t)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPublicKeyControllerDiscovery(t *testing.T) {
	key, certificate := controllerDiscoveryCertificate(t)
	controller := controllerDiscoveryService("sealed-secrets", "sealed-secrets", "controller", "http")
	metrics := controllerDiscoveryService("sealed-secrets", "sealed-secrets-metrics", "metrics", "metrics")
	cases := []struct {
		name            string
		namespace       string
		controllerName  string
		initialStatus   int
		discover        bool
		discoveryStatus int
		services        []corev1.Service
		resolved        *corev1.Service
	}{
		{name: "legacy default", initialStatus: http.StatusOK, resolved: ptrDiscoveryService(controllerDiscoveryService("kube-system", "sealed-secrets-controller", "controller", "http"))},
		{name: "helm controller excludes metrics", initialStatus: http.StatusNotFound, discover: true, discoveryStatus: http.StatusOK, services: []corev1.Service{metrics, controller}, resolved: &controller},
		{name: "forbidden default", initialStatus: http.StatusForbidden, discover: true, discoveryStatus: http.StatusOK, services: []corev1.Service{controller}, resolved: &controller},
		{name: "explicit namespace auto name", namespace: "sealed-secrets", initialStatus: http.StatusNotFound, discover: true, discoveryStatus: http.StatusOK, services: []corev1.Service{metrics, controller}, resolved: &controller},
		{name: "explicit name auto namespace", controllerName: "sealed-secrets", initialStatus: http.StatusNotFound, discover: true, discoveryStatus: http.StatusOK, services: []corev1.Service{controller}, resolved: &controller},
		{name: "explicit pair missing", namespace: "custom", controllerName: "custom-controller", initialStatus: http.StatusNotFound},
		{name: "explicit pair forbidden", namespace: "custom", controllerName: "custom-controller", initialStatus: http.StatusForbidden},
		{name: "expired authentication", initialStatus: http.StatusUnauthorized},
		{name: "ambiguous controllers", initialStatus: http.StatusNotFound, discover: true, discoveryStatus: http.StatusOK, services: []corev1.Service{controller, controllerDiscoveryService("other", "sealed-secrets", "controller", "http")}},
		{name: "metrics only", initialStatus: http.StatusNotFound, discover: true, discoveryStatus: http.StatusOK, services: []corev1.Service{metrics}},
		{name: "controller missing ports", initialStatus: http.StatusNotFound, discover: true, discoveryStatus: http.StatusOK, services: []corev1.Service{controllerDiscoveryService("sealed-secrets", "sealed-secrets", "controller", "")}},
		{name: "no controllers", initialStatus: http.StatusNotFound, discover: true, discoveryStatus: http.StatusOK},
		{name: "discovery forbidden", initialStatus: http.StatusNotFound, discover: true, discoveryStatus: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			initialNamespace, initialName := tc.namespace, tc.controllerName
			if initialNamespace == "" {
				initialNamespace = "kube-system"
			}
			if initialName == "" {
				initialName = "sealed-secrets-controller"
			}
			initialPath := "/api/v1/namespaces/" + initialNamespace + "/services/" + initialName
			listPath := "/api/v1/services"
			if tc.namespace != "" {
				listPath = "/api/v1/namespaces/" + tc.namespace + "/services"
			}
			discovered, fetched := false, false
			setupControllerDiscoveryTest(t, tc.namespace, tc.controllerName, func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || strings.Contains(req.URL.Path, "/secrets") {
					t.Errorf("public-key lookup made unexpected request: %s %s", req.Method, req.URL)
					return nil, errors.New("unexpected public-key request")
				}
				if req.URL.Path == initialPath {
					return controllerDiscoveryJSON(t, tc.initialStatus, controllerDiscoveryService(initialNamespace, initialName, "controller", "http")), nil
				}
				if req.URL.Path == listPath {
					if !tc.discover {
						t.Error("discovery ignored explicit controller settings or authentication failure")
						return nil, errors.New("unexpected discovery")
					}
					discovered = true
					if tc.controllerName != "" && req.URL.Query().Get("fieldSelector") != "metadata.name="+tc.controllerName {
						t.Error("service discovery did not constrain the explicit controller name")
					}
					return controllerDiscoveryJSON(t, tc.discoveryStatus, &corev1.ServiceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceList"}, Items: tc.services}), nil
				}
				if tc.resolved != nil {
					if req.URL.Path == "/api/v1/namespaces/"+tc.resolved.Namespace+"/services/"+tc.resolved.Name {
						return controllerDiscoveryJSON(t, http.StatusOK, tc.resolved), nil
					}
					if strings.HasSuffix(req.URL.Path, "/proxy/v1/cert.pem") && strings.Contains(req.URL.Path, "/namespaces/"+tc.resolved.Namespace+"/") && strings.Contains(req.URL.Path, ":"+tc.resolved.Name+":") {
						fetched = true
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/x-pem-file"}}, Body: io.NopCloser(bytes.NewReader(certificate))}, nil
					}
				}
				t.Errorf("unexpected request: %s", req.URL)
				return nil, errors.New("unexpected request")
			})
			result, err := getPublicKey(context.Background())
			if clientConfig.client.AcceptContentTypes != "" {
				t.Fatal("certificate fetch mutated the shared REST config")
			}
			if tc.resolved == nil {
				if err == nil || result != nil || fetched {
					t.Fatalf("expected controller discovery failure, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			} else if result.N.Cmp(key.N) != 0 || result.E != key.E || !fetched {
				t.Fatal("did not fetch the selected controller's certificate")
			}
			if discovered != tc.discover {
				t.Fatalf("discovery performed = %v, want %v", discovered, tc.discover)
			}
		})
	}
}

func ptrDiscoveryService(service corev1.Service) *corev1.Service { return &service }

func TestPublicKeyControllerServicePorts(t *testing.T) {
	_, certificate := controllerDiscoveryCertificate(t)
	for _, withHTTP := range []bool{false, true} {
		t.Run(fmt.Sprintf("http=%v", withHTTP), func(t *testing.T) {
			service := controllerDiscoveryService("custom", "controller", "controller", "")
			if withHTTP {
				service.Spec.Ports = []corev1.ServicePort{{Name: "metrics", Port: 8081}, {Name: "http", Port: 8080}}
			}
			fetched := false
			setupControllerDiscoveryTest(t, "custom", "controller", func(req *http.Request) (*http.Response, error) {
				switch req.URL.Path {
				case "/api/v1/namespaces/custom/services/controller":
					return controllerDiscoveryJSON(t, http.StatusOK, service), nil
				case "/api/v1/namespaces/custom/services/http:controller:http/proxy/v1/cert.pem":
					if !withHTTP {
						t.Error("attempted certificate request for a service without ports")
					}
					fetched = true
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/x-pem-file"}}, Body: io.NopCloser(bytes.NewReader(certificate))}, nil
				default:
					t.Errorf("unexpected service port request: %s", req.URL)
					return nil, errors.New("unexpected service port request")
				}
			})
			key, err := getPublicKey(context.Background())
			if withHTTP {
				if err != nil || key == nil || !fetched {
					t.Fatalf("HTTP port was not preferred over metrics: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "no ports") || fetched {
				t.Fatalf("expected a no-ports error without certificate request, got %v", err)
			}
		})
	}
}
