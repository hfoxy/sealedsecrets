package main

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

const (
	defaultControllerNamespace = metav1.NamespaceSystem
	defaultControllerName      = "sealed-secrets-controller"
	activeKeySelector          = "sealedsecrets.bitnami.com/sealed-secrets-key=active"
)

func activeSealingKeys(ctx context.Context, client *ClientConfig) (*corev1.SecretList, error) {
	namespace := ControllerNamespace
	if namespace == "" {
		namespace = defaultControllerNamespace
	}
	keys, err := client.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{LabelSelector: activeKeySelector})
	if err == nil && len(keys.Items) > 0 {
		return keys, nil
	}
	if ControllerNamespace != "" || (err != nil && !canDiscoverController(err)) {
		return nil, sealingKeyError(client, namespace, err)
	}

	// Discover using metadata only. Private key material is fetched only from
	// the selected namespace, and keys from different controllers are not mixed.
	metadataClient, err := metadata.NewForConfig(client.client)
	if err != nil {
		return nil, fmt.Errorf("unable to create key discovery client: %w", err)
	}
	keyMetadata, err := metadataClient.Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}).List(ctx, metav1.ListOptions{LabelSelector: activeKeySelector})
	if err != nil {
		return nil, fmt.Errorf("unable to discover sealing-key namespace in context %q; set --controller-namespace explicitly: %w", client.context, err)
	}
	var namespaces []string
	for _, key := range keyMetadata.Items {
		if !slices.Contains(namespaces, key.Namespace) {
			namespaces = append(namespaces, key.Namespace)
		}
	}
	slices.Sort(namespaces)
	switch len(namespaces) {
	case 0:
		return nil, fmt.Errorf("no active sealing key found in context %q; checked %q and discovered no active keys in other namespaces; set --controller-namespace explicitly", client.context, namespace)
	case 1:
		namespace = namespaces[0]
	default:
		return nil, fmt.Errorf("active sealing keys found in multiple namespaces in context %q: %s; select one with --controller-namespace", client.context, strings.Join(namespaces, ", "))
	}
	keys, err = client.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{LabelSelector: activeKeySelector})
	if err != nil || len(keys.Items) == 0 {
		return nil, sealingKeyError(client, namespace, err)
	}
	return keys, nil
}

func sealingKeyError(client *ClientConfig, namespace string, err error) error {
	if err != nil {
		return fmt.Errorf("unable to list active sealing keys in namespace %q in context %q: %w", namespace, client.context, err)
	}
	return fmt.Errorf("no active sealing key found in namespace %q in context %q; check --controller-namespace", namespace, client.context)
}

func canDiscoverController(err error) bool {
	return apierrors.IsNotFound(err) || apierrors.IsForbidden(err)
}

func findControllerService(ctx context.Context, client *ClientConfig) (*corev1.Service, error) {
	namespace, name := ControllerNamespace, ControllerName
	if namespace == "" {
		namespace = defaultControllerNamespace
	}
	if name == "" {
		name = defaultControllerName
	}
	service, err := client.clientset.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return service, nil
	}
	if (ControllerNamespace != "" && ControllerName != "") || !canDiscoverController(err) {
		return nil, fmt.Errorf("unable to get controller service %s/%s in context %q: %w", namespace, name, client.context, err)
	}
	options := metav1.ListOptions{}
	if ControllerName != "" {
		options.FieldSelector = fields.OneTermEqualSelector("metadata.name", ControllerName).String()
	}
	services, err := client.clientset.CoreV1().Services(ControllerNamespace).List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("unable to discover controller service in context %q; set --controller-namespace and --controller-name explicitly: %w", client.context, err)
	}
	var candidates []corev1.Service
	var names []string
	for _, service := range services.Items {
		if ControllerName != "" && service.Name != ControllerName {
			continue
		}
		if ControllerName == "" && !isControllerService(service) {
			continue
		}
		candidates = append(candidates, service)
		names = append(names, service.Namespace+"/"+service.Name)
	}
	slices.Sort(names)
	switch len(candidates) {
	case 0:
		return nil, fmt.Errorf("no controller service found in context %q; set --controller-namespace and --controller-name explicitly", client.context)
	case 1:
		return &candidates[0], nil
	default:
		return nil, fmt.Errorf("multiple controller services found in context %q: %s; select one with --controller-namespace and --controller-name", client.context, strings.Join(names, ", "))
	}
}

func isControllerService(service corev1.Service) bool {
	if service.Labels["app.kubernetes.io/component"] == "metrics" {
		return false
	}
	knownController := service.Labels["app.kubernetes.io/name"] == "sealed-secrets" ||
		service.Labels["name"] == defaultControllerName ||
		service.Name == defaultControllerName || service.Name == "sealed-secrets"
	if !knownController {
		return false
	}
	for _, port := range service.Spec.Ports {
		if port.Name == "http" && port.Protocol != corev1.ProtocolUDP {
			return true
		}
	}
	return false
}

func openControllerCertificate(ctx context.Context, client *ClientConfig, service *corev1.Service) (io.ReadCloser, error) {
	if len(service.Spec.Ports) == 0 {
		return nil, fmt.Errorf("controller service %s/%s has no ports", service.Namespace, service.Name)
	}
	portName := service.Spec.Ports[0].Name
	for _, port := range service.Spec.Ports {
		if port.Name == "http" {
			portName = port.Name
			break
		}
	}
	config := rest.CopyConfig(client.client)
	config.AcceptContentTypes = "application/x-pem-file, */*"
	certClient, err := coreclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create certificate client: %w", err)
	}
	return certClient.Services(service.Namespace).ProxyGet("http", service.Name, portName, "/v1/cert.pem", nil).Stream(ctx)
}
