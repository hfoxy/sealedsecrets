package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/kubeseal"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"
)

var Reseal bool
var KeepTemplate bool
var Scope v1alpha1.SealingScope

func Seal(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}
	if len(args) > 1 && OutputFile != "" {
		return fmt.Errorf("cannot specify output file with multiple input files")
	}
	for _, arg := range args {
		outputName := OutputFile
		if outputName == "" {
			outputName = strings.TrimSuffix(arg, ".unsealed.yaml") + ".yaml"
		}
		if err := seal(cmd, arg, outputName); err != nil {
			return err
		}
	}
	return nil
}

func seal(cmd *cobra.Command, arg string, outputName string) error {
	_, err := os.Lstat(outputName)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unable to inspect output file %s: %w", outputName, err)
	}
	if exists && !Force {
		return fmt.Errorf("output file %s already exists, use --force to overwrite", outputName)
	}

	sourceData, err := os.ReadFile(arg)
	if err != nil {
		return fmt.Errorf("unable to read file %s: %w", arg, err)
	}
	sourceSecret := &corev1.Secret{}
	if err := decodeManifest(sourceData, sourceSecret); err != nil {
		return fmt.Errorf("unable to read source secret %s: %w", arg, err)
	}
	if sourceSecret.APIVersion != "v1" || sourceSecret.Kind != "Secret" || sourceSecret.Name == "" {
		return fmt.Errorf("source %s must be a v1 Secret with metadata.name", arg)
	}

	ns := Namespace
	if ns == "" {
		ns = sourceSecret.Namespace
	}
	if ns == "" {
		ns = sourceSecret.Annotations[NamespaceKey]
	}
	if ns == "" {
		return fmt.Errorf("unable to determine namespace")
	}
	nsFromFile := ns == sourceSecret.Namespace
	sourceSecret.Namespace = ns
	// An explicitly requested strict scope must clear inherited wide-scope annotations.
	if Scope != v1alpha1.DefaultScope || cmd.Flags().Changed("scope") {
		sourceSecret.Annotations = v1alpha1.UpdateScopeAnnotations(sourceSecret.Annotations, Scope)
	}

	var originalSealedSecret *v1alpha1.SealedSecret
	var originalSecret *corev1.Secret
	if !Reseal && exists {
		var originalData string
		originalData, originalSealedSecret, err = unsealSecretForUpdate(cmd, outputName)
		if err != nil {
			return err
		}
		originalSecret = &corev1.Secret{}
		if err := yaml.Unmarshal([]byte(originalData), originalSecret); err != nil {
			return fmt.Errorf("unable to unmarshal original secret %s: %w", outputName, err)
		}
	}

	key, err := getPublicKey(cmd.Context())
	if err != nil {
		return fmt.Errorf("unable to get public key: %w", err)
	}
	sealedSecret, skipped, err := buildSealedSecret(sourceSecret, originalSecret, originalSealedSecret, key)
	if err != nil {
		return fmt.Errorf("unable to seal secret: %w", err)
	}
	if len(skipped) > 0 {
		fmt.Printf("Skipped %d unchanged keys: %s\n", len(skipped), strings.Join(skipped, ", "))
	}

	if KeepTemplate {
		if !nsFromFile {
			if sealedSecret.Annotations == nil {
				sealedSecret.Annotations = make(map[string]string)
			}
			sealedSecret.Annotations[NamespaceKey] = ns
		} else {
			delete(sealedSecret.Annotations, NamespaceKey)
		}
	}
	data, err := marshalSealedSecret(sealedSecret, KeepTemplate)
	if err != nil {
		return fmt.Errorf("unable to marshal sealed secret: %w", err)
	}
	if err := writeSealedFile(outputName, data, Force); err != nil {
		return fmt.Errorf("unable to write to file %s: %w", outputName, err)
	}
	fmt.Printf("Sealed secret from %s to %s\n", arg, outputName)
	return nil
}

// Keep omitted keys for incremental updates and reuse ciphertext only when its
// plaintext and encryption label still match. stringData takes precedence over data.
func buildSealedSecret(source, original *corev1.Secret, previous *v1alpha1.SealedSecret, key *rsa.PublicKey) (*v1alpha1.SealedSecret, []string, error) {
	source = source.DeepCopy()
	skipped := make([]string, 0)
	if original != nil && previous != nil {
		label := v1alpha1.EncryptionLabel(source.Namespace, source.Name, v1alpha1.SecretScope(source))
		previousLabel := v1alpha1.EncryptionLabel(previous.Namespace, previous.Name, v1alpha1.SecretScope(previous))
		for k, oldValue := range original.Data {
			value, present := source.Data[k]
			if text, ok := source.StringData[k]; ok {
				value, present = []byte(text), true
			}
			if !present {
				if source.Data == nil {
					source.Data = make(map[string][]byte)
				}
				source.Data[k] = oldValue
				value = oldValue
			}
			// Template output may differ from the plaintext inside this ciphertext.
			_, templated := previous.Spec.Template.Data[k]
			if !templated && bytes.Equal(label, previousLabel) && bytes.Equal(value, oldValue) && previous.Spec.EncryptedData[k] != "" {
				delete(source.Data, k)
				delete(source.StringData, k)
				skipped = append(skipped, k)
			}
		}
	}
	sort.Strings(skipped)
	sourceData, err := yaml.Marshal(source)
	if err != nil {
		return nil, nil, err
	}
	w := &bytes.Buffer{}
	// Namespace is already resolved, so kubeseal does not need a cluster client.
	if err := kubeseal.Seal(nil, "yaml", bytes.NewReader(sourceData), w, scheme.Codecs, key, v1alpha1.DefaultScope, true, source.Name, source.Namespace); err != nil {
		return nil, nil, err
	}
	sealedSecret := &v1alpha1.SealedSecret{}
	if err := yaml.Unmarshal(w.Bytes(), sealedSecret); err != nil {
		return nil, nil, err
	}
	for _, k := range skipped {
		sealedSecret.Spec.EncryptedData[k] = previous.Spec.EncryptedData[k]
	}
	return sealedSecret, skipped, nil
}

func marshalSealedSecret(secret *v1alpha1.SealedSecret, keepTemplate bool) ([]byte, error) {
	data, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}
	var document map[string]interface{}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if metadata, ok := document["metadata"].(map[string]interface{}); ok {
		delete(metadata, "creationTimestamp")
	}
	if spec, ok := document["spec"].(map[string]interface{}); ok {
		if !keepTemplate {
			delete(spec, "template")
		} else if template, ok := spec["template"].(map[string]interface{}); ok {
			if metadata, ok := template["metadata"].(map[string]interface{}); ok {
				delete(metadata, "creationTimestamp")
			}
		}
	}
	return yaml.Marshal(document)
}

func writeSealedFile(name string, data []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !force {
		flags |= os.O_EXCL
	}
	file, err := os.OpenFile(name, flags, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Close()
}
