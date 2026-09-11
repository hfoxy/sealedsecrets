package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/kubeseal"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"
)

var Decode bool

const NamespaceKey = "sealedsecrets.hfox.me/namespace"

func Unseal(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

	pairs, err := resolveSecretFiles(args, OutputFile, false)
	if err != nil {
		return err
	}
	for _, pair := range pairs {
		if err := unseal(cmd, pair.source, pair.destination); err != nil {
			return err
		}
	}

	return nil
}

func unsealSecret(cmd *cobra.Command, name string) (string, *v1alpha1.SealedSecret, error) {
	return unsealSecretWithNamespace(cmd, name, false)
}

// Updates must decrypt using the original encryption namespace before sealing
// for the namespace selected by the current command.
func unsealSecretForUpdate(cmd *cobra.Command, name string) (string, *v1alpha1.SealedSecret, error) {
	return unsealSecretWithNamespace(cmd, name, true)
}

func unsealSecretWithNamespace(cmd *cobra.Command, name string, preferManifestNamespace bool) (string, *v1alpha1.SealedSecret, error) {
	fileName := name
	data, err := os.ReadFile(fileName)
	if err != nil {
		return "", nil, fmt.Errorf("unable to read file %s: %w", name, err)
	}

	sealedSecret := v1alpha1.SealedSecret{}
	err = decodeManifest(data, &sealedSecret)
	if err != nil {
		return "", nil, fmt.Errorf("unable to unmarshal secret %s: %w", name, err)
	}
	if sealedSecret.APIVersion != "bitnami.com/v1alpha1" || sealedSecret.Kind != "SealedSecret" {
		return "", nil, fmt.Errorf("file %s must contain a bitnami.com/v1alpha1 SealedSecret", name)
	}

	ns := Namespace
	nsAnno, ok := sealedSecret.ObjectMeta.Annotations[NamespaceKey]
	if preferManifestNamespace {
		if sealedSecret.Namespace != "" {
			ns = sealedSecret.Namespace
		} else if nsAnno != "" {
			ns = nsAnno
		}
	}
	if ns == "" && sealedSecret.Namespace == "" && (!ok || nsAnno == "") {
		return "", nil, fmt.Errorf("unable to determine namespace for %s", name)
	} else if ns == "" && sealedSecret.Namespace != "" {
		fmt.Printf("Using namespace from secret\n")
		ns = sealedSecret.Namespace
	} else if ns == "" && ok && nsAnno != "" {
		fmt.Printf("Using namespace from annotation\n")
		ns = nsAnno
	}

	if sealedSecret.ObjectMeta.Namespace != ns {
		sealedSecret.ObjectMeta.Namespace = ns
		data, err = yaml.Marshal(sealedSecret)
		if err != nil {
			return "", nil, fmt.Errorf("unable to remarshal secret %s: %w", name, err)
		}
	}

	client, err := getKubeClient()
	if err != nil {
		return "", nil, fmt.Errorf("unable to get kubernetes client: %w", err)
	}

	key, err := getPrivateKey(cmd.Context())
	if err != nil {
		return "", nil, err
	}

	fmt.Printf("Unsealing '%s' in context '%s', namespace '%s'\n", fileName, client.context, ns)

	temp, err := os.CreateTemp(os.TempDir(), "ss-")
	if err != nil {
		return "", nil, fmt.Errorf("unable to create temp file: %w", err)
	}

	defer func() {
		_ = temp.Close()
		removeErr := os.Remove(temp.Name())
		if removeErr != nil {
			ErrorLogger.Printf("unable to remove temp file: %v", removeErr)
		}
	}()

	_, err = temp.WriteString(key)
	if err != nil {
		return "", nil, fmt.Errorf("unable to write to temp file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return "", nil, fmt.Errorf("unable to close temp file: %w", err)
	}

	reader := bytes.NewReader(data)

	w := &bytes.Buffer{}
	err = kubeseal.UnsealSealedSecret(w, reader, []string{temp.Name()}, "yaml", scheme.Codecs)
	if err != nil {
		return "", nil, fmt.Errorf("unable to unseal secret %s: %w", name, err)
	}

	out := strings.TrimPrefix(w.String(), "---\n")
	return out, &sealedSecret, nil
}

func unseal(cmd *cobra.Command, arg string, outputName string) error {
	if !Force {
		if _, err := os.Lstat(outputName); err == nil {
			return fmt.Errorf("output file %s already exists, use --force to overwrite", outputName)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("unable to inspect output file %s: %w", outputName, err)
		}
	}

	out, sealedSecret, err := unsealSecret(cmd, arg)
	if err != nil {
		return err
	}

	secret := corev1.Secret{}
	err = yaml.Unmarshal([]byte(out), &secret)
	if err != nil {
		return fmt.Errorf("unable to unmarshal unsealed secret: %w", err)
	}

	if Decode {
		if secret.StringData == nil {
			secret.StringData = make(map[string]string)
		}
		for k, data := range secret.Data {
			// stringData must contain UTF-8; binary values must stay base64-encoded
			// in data to survive YAML/JSON serialization without replacement bytes.
			if utf8.Valid(data) {
				secret.StringData[k] = string(data)
				delete(secret.Data, k)
			}
		}
	}

	if sealedSecret.ObjectMeta.Namespace == "" {
		secret.ObjectMeta.Namespace = Namespace
		if secret.ObjectMeta.Annotations == nil {
			secret.ObjectMeta.Annotations = make(map[string]string)
		}
		secret.ObjectMeta.Annotations[NamespaceKey] = Namespace
	} else {
		secret.ObjectMeta.Namespace = sealedSecret.ObjectMeta.Namespace
	}

	b, err := yaml.Marshal(secret)
	if err != nil {
		return fmt.Errorf("unable to marshal unsealed secret: %w", err)
	}

	if err := writeUnsealedFile(outputName, b, Force); err != nil {
		return err
	}

	fmt.Printf("Unsealed secret written to %s\n", outputName)
	return nil
}

// writeUnsealedFile keeps plaintext secrets private, including when replacing an
// existing file, and checks for concurrent file creation when force is disabled.
func writeUnsealedFile(name string, data []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if !force {
		flags |= os.O_EXCL
	}
	file, err := os.OpenFile(name, flags, 0600)
	if err != nil {
		return fmt.Errorf("unable to write file %s: %w", name, err)
	}
	defer file.Close()

	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("unable to restrict permissions on file %s: %w", name, err)
	}
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("unable to truncate file %s: %w", name, err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("unable to write file %s: %w", name, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("unable to close file %s: %w", name, err)
	}
	return nil
}
