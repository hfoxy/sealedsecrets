package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/kubeseal"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"os"
	"sigs.k8s.io/yaml"
	"strings"
)

var Reseal bool
var KeepTemplate bool
var Scope v1alpha1.SealingScope

func Seal(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

	if len(args) > 1 {
		if OutputFile != "" {
			return fmt.Errorf("cannot specify output file with multiple input files")
		}

		for _, arg := range args {
			outputName := strings.TrimSuffix(arg, ".unsealed.yaml") + ".yaml"
			err := seal(cmd, arg, outputName)
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
			outputName = strings.TrimSuffix(args[0], ".unsealed.yaml") + ".yaml"
		}

		err := seal(cmd, args[0], outputName)
		if err != nil {
			if errors.Is(err, ErrStop) {
				return nil
			}

			return err
		}
	}

	return nil
}

func seal(cmd *cobra.Command, arg string, outputName string) error {
	// if outputName exists
	_, err := os.Stat(outputName)
	exists := err == nil
	if exists && !Force {
		ErrorLogger.Printf("output file %s already exists, use --force to overwrite", outputName)
		return ErrStop
	}

	sourceData, err := os.ReadFile(arg)
	if err != nil {
		ErrorLogger.Printf("unable to read file %s: %v", arg, err)
		return ErrStop
	}

	sourceSecret := corev1.Secret{}
	err = yaml.Unmarshal(sourceData, &sourceSecret)
	if err != nil {
		ErrorLogger.Printf("unable to unmarshal source secret %s: %v", arg, err)
		return ErrStop
	}

	reseal := Reseal
	if _, err = os.Stat(outputName); errors.Is(err, os.ErrNotExist) {
		reseal = true
	}

	var originalSealedSecret *v1alpha1.SealedSecret
	skipped := make([]string, 0, len(sourceSecret.Data))
	if !reseal {
		originalSecret := corev1.Secret{}

		var originalSecretData string
		originalSecretData, originalSealedSecret, err = unsealSecret(cmd, outputName)
		if err != nil {
			return err
		}

		err = yaml.Unmarshal([]byte(originalSecretData), &originalSecret)
		if err != nil {
			ErrorLogger.Printf("unable to unmarshal original secret %s: %v", arg, err)
			return ErrStop
		}

		for k, original := range originalSecret.Data {
			source := sourceSecret.Data[k]
			if source == nil {
				source = []byte(sourceSecret.StringData[k])
			}

			if source == nil {
				if sourceSecret.Data == nil {
					sourceSecret.Data = make(map[string][]byte)
				}

				sourceSecret.Data[k] = original
			} else if string(original) == string(source) {
				delete(sourceSecret.StringData, k)
				delete(sourceSecret.Data, k)
				skipped = append(skipped, k)
			}
		}

		if len(skipped) > 0 {
			fmt.Printf("Skipped %d unchanged keys: %s\n", len(skipped), strings.Join(skipped, ", "))
		}

		if len(sourceSecret.Data) == 0 && len(sourceSecret.StringData) == 0 {
			fmt.Printf("No changes to seal\n")
			return nil
		}

		sourceData, err = yaml.Marshal(sourceSecret)
		if err != nil {
			ErrorLogger.Printf("unable to marshal source secret: %v", err)
			return ErrStop
		}
	}

	client, err := getKubeClient()
	if err != nil {
		return fmt.Errorf("unable to get kubernetes client: %v", err)
	}

	key, err := getPublicKey(cmd.Context())
	if err != nil {
		ErrorLogger.Printf("unable to get private key: %v", err)
		return ErrStop
	}

	nsFromFile := false
	ns := Namespace
	nsAnno, ok := sourceSecret.ObjectMeta.Annotations[NamespaceKey]
	if ns == "" && sourceSecret.Namespace == "" && (!ok || nsAnno == "") {
		ErrorLogger.Printf("unable to determine namespace\n")
		return ErrStop
	} else if ns == "" && sourceSecret.Namespace != "" {
		fmt.Printf("Using namespace from secret\n")
		ns = sourceSecret.Namespace
	} else if ns == "" && ok && nsAnno != "" {
		fmt.Printf("Using namespace from annotation\n")
		ns = nsAnno
	}

	if ns == sourceSecret.Namespace {
		nsFromFile = true
	}

	r := bytes.NewReader(sourceData)
	w := &bytes.Buffer{}

	err = kubeseal.Seal(client, "yaml", r, w, scheme.Codecs, key, Scope, true, sourceSecret.ObjectMeta.Name, ns)
	if err != nil {
		ErrorLogger.Printf("unable to seal secret: %v", err)
		return ErrStop
	}

	sealedSecret := v1alpha1.SealedSecret{}
	err = yaml.Unmarshal(w.Bytes(), &sealedSecret)
	if err != nil {
		ErrorLogger.Printf("unable to unmarshal sealed secret: %v", err)
		return ErrStop
	}

	if !reseal {
		for _, k := range skipped {
			sealedSecret.Spec.EncryptedData[k] = originalSealedSecret.Spec.EncryptedData[k]
		}
	}

	if !KeepTemplate {
		sealedSecret.Spec.Template = v1alpha1.SecretTemplateSpec{}
	} else if !nsFromFile {
		sealedSecret.ObjectMeta.Annotations[NamespaceKey] = ns
	} else if nsFromFile {
		delete(sealedSecret.ObjectMeta.Annotations, NamespaceKey)
		sealedSecret.Namespace = ns
	}

	sealedSecret.ObjectMeta.CreationTimestamp = v1.Time{}

	data, err := yaml.Marshal(sealedSecret)
	if err != nil {
		ErrorLogger.Printf("unable to marshal sealed secret: %v", err)
		return ErrStop
	}

	data = bytes.Replace(data, []byte("  creationTimestamp: null\n"), []byte(""), -1)
	data = bytes.TrimPrefix(data, []byte("---\n"))

	if !KeepTemplate {
		data = bytes.Replace(data, []byte("  template:\n    metadata:\n    "), []byte(""), -1)
	}

	err = os.WriteFile(outputName, data, 0644)
	if err != nil {
		ErrorLogger.Printf("unable to write to file %s: %v", outputName, err)
		return ErrStop
	}

	fmt.Printf("Sealed secret from %s to %s\n", arg, outputName)
	return nil
}
