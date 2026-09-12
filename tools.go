package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/bitnami/sealed-secrets/pkg/kubeseal"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

var ErrorLogger = log.New(os.Stderr, "ERROR: ", 0)

// Empty values enable discovery; explicit settings always take precedence.
var ControllerNamespace string
var ControllerName string

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

	secrets, err := activeSealingKeys(ctx, client)
	if err != nil {
		return "", err
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

	service, err := findControllerService(ctx, client)
	if err != nil {
		return nil, err
	}
	r, err := openControllerCertificate(ctx, client, service)
	if err != nil {
		return nil, fmt.Errorf("unable to open cert: %v", err)
	}
	defer r.Close()

	key, err := kubeseal.ParseKey(r)
	if err != nil {
		return nil, fmt.Errorf("unable to parse key: %v", err)
	}

	return key, nil
}
