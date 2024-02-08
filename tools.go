package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/bitnami-labs/sealed-secrets/pkg/kubeseal"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"os"
	"sigs.k8s.io/yaml"
	"strings"
)

var ErrorLogger = log.New(os.Stderr, "ERROR: ", 0)

var ControllerNamespace = metav1.NamespaceSystem
var ControllerName = "sealed-secrets-controller"

func getHome() string {
	dirname, err := os.UserHomeDir()
	if err != nil {
		ErrorLogger.Printf("unable to get user home directory: %v", err)
		return ""
	}

	return dirname
}

func getPrivateKey(ctx context.Context) (string, error) {
	client, err := getKubeClient()
	if err != nil {
		return "", fmt.Errorf("unable to get kubernetes client: %v", err)
	}

	secrets, err := client.clientset.CoreV1().Secrets(ControllerNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "sealedsecrets.bitnami.com/sealed-secrets-key=active",
	})

	if err != nil {
		return "", fmt.Errorf("unable to list secrets: %v", err)
	}

	if len(secrets.Items) == 0 {
		return "", fmt.Errorf("no active key found")
	}

	output := strings.Builder{}
	for _, secret := range secrets.Items {
		secret.APIVersion = corev1.SchemeGroupVersion.String()
		secret.Kind = "Secret"
		secret.ObjectMeta.ManagedFields = nil

		var data []byte
		data, err = yaml.Marshal(secret)
		if err != nil {
			return "", fmt.Errorf("unable to marshal secret: %v", err)
		}

		output.WriteString(string(data))
		output.WriteString("---\n")
	}

	return output.String(), nil
}

func getPublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	client, err := getKubeClient()
	if err != nil {
		return nil, fmt.Errorf("unable to get kubernetes client: %v", err)
	}

	r, err := kubeseal.OpenCert(ctx, client, ControllerNamespace, ControllerName, "")
	if err != nil {
		return nil, fmt.Errorf("unable to open cert: %v", err)
	}

	key, err := kubeseal.ParseKey(r)
	if err != nil {
		return nil, fmt.Errorf("unable to parse key: %v", err)
	}

	return key, nil
}
