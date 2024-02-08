package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/kubeseal"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"os"
	"sigs.k8s.io/yaml"
	"strings"
)

var ErrStop = fmt.Errorf("stop")
var Decode bool

const NamespaceKey = "sealedsecrets.hfox.me/namespace"

func Unseal(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

	if len(args) > 1 {
		if OutputFile != "" {
			return fmt.Errorf("cannot specify output file with multiple input files")
		}

		for _, arg := range args {
			outputName := strings.TrimSuffix(arg, ".yaml") + ".unsealed.yaml"
			err := unseal(cmd, arg, outputName)
			if err != nil {
				if errors.Is(err, ErrStop) {
					return nil
				}

				return err
			}
		}

		return nil
	} else {
		outputName := OutputFile
		if outputName == "" {
			outputName = strings.TrimSuffix(args[0], ".yaml") + ".unsealed.yaml"
		}

		err := unseal(cmd, args[0], outputName)
		if err != nil {
			if errors.Is(err, ErrStop) {
				return nil
			}

			return err
		}
	}

	return nil
}

func unsealSecret(cmd *cobra.Command, name string) (string, *v1alpha1.SealedSecret, error) {
	client, err := getKubeClient()
	if err != nil {
		return "", nil, fmt.Errorf("unable to get kubernetes client: %v", err)
	}

	key, err := getPrivateKey(cmd.Context())
	if err != nil {
		return "", nil, err
	}

	fileName := name
	data, err := os.ReadFile(fileName)
	if err != nil {
		ErrorLogger.Printf("unable to read file: %v", err)
		return "", nil, ErrStop
	}

	sealedSecret := v1alpha1.SealedSecret{}
	err = yaml.Unmarshal(data, &sealedSecret)
	if err != nil {
		ErrorLogger.Printf("unable to unmarshal secret: %v", err)
		return "", nil, ErrStop
	}

	ns := Namespace
	nsAnno, ok := sealedSecret.ObjectMeta.Annotations[NamespaceKey]
	if ns == "" && sealedSecret.Namespace == "" && (!ok || nsAnno == "") {
		ErrorLogger.Printf("unable to determine namespace\n")
		return "", nil, ErrStop
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
			ErrorLogger.Printf("unable to remarshal secret: %v", err)
			return "", nil, ErrStop
		}
	}

	fmt.Printf("Unsealing '%s' in context '%s', namespace '%s'\n", fileName, client.context, ns)

	temp, err := os.CreateTemp(os.TempDir(), "ss-")
	if err != nil {
		ErrorLogger.Printf("unable to create temp file: %v", err)
		return "", nil, ErrStop
	}

	defer func() {
		removeErr := os.Remove(temp.Name())
		if removeErr != nil {
			ErrorLogger.Printf("unable to remove temp file: %v", removeErr)
		}
	}()

	_, err = temp.WriteString(key)
	if err != nil {
		ErrorLogger.Printf("unable to write to temp file: %v", err)
		return "", nil, ErrStop
	}

	reader := bytes.NewReader(data)

	w := &bytes.Buffer{}
	err = kubeseal.UnsealSealedSecret(w, reader, []string{temp.Name()}, "yaml", scheme.Codecs)
	if err != nil {
		ErrorLogger.Printf("unable to unseal secret %s: %v", name, err)
		return "", nil, ErrStop
	}

	out := strings.TrimPrefix(w.String(), "---\n")
	return out, &sealedSecret, nil
}

func unseal(cmd *cobra.Command, arg string, outputName string) error {
	out, sealedSecret, err := unsealSecret(cmd, arg)
	if err != nil {
		return err
	}

	secret := corev1.Secret{}
	err = yaml.Unmarshal([]byte(out), &secret)
	if err != nil {
		ErrorLogger.Printf("unable to unmarshal unsealed secret: %v", err)
		return ErrStop
	}

	if Decode {
		keys := make([]string, 0, len(secret.Data))
		for k := range secret.Data {
			keys = append(keys, k)
		}

		secret.StringData = make(map[string]string, len(keys))

		for _, k := range keys {
			d := secret.Data[k]
			secret.StringData[k] = string(d)
			delete(secret.Data, k)
		}
	}

	if sealedSecret.ObjectMeta.Namespace == "" {
		secret.ObjectMeta.Namespace = Namespace
		secret.ObjectMeta.Annotations[NamespaceKey] = Namespace
	} else {
		secret.ObjectMeta.Namespace = sealedSecret.ObjectMeta.Namespace
	}

	b, err := yaml.Marshal(secret)
	if err != nil {
		ErrorLogger.Printf("unable to marshal unsealed secret: %v", err)
		return ErrStop
	}

	out = string(b)

	err = os.WriteFile(outputName, []byte(out), 0644)
	if err != nil {
		ErrorLogger.Printf("unable to write to file: %v", err)
		return ErrStop
	}

	fmt.Printf("Unsealed secret written to %s\n", outputName)
	return nil
}
