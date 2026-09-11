package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type secretFilePair struct {
	source      string
	destination string
}

// Resolve the entire batch before writing, so one output cannot replace a
// source or another destination selected by the same invocation.
func resolveSecretFiles(args []string, output string, sealing bool) ([]secretFilePair, error) {
	if len(args) > 1 && output != "" {
		return nil, fmt.Errorf("cannot specify output file with multiple input files")
	}
	if output != "" && !Force {
		if _, err := os.Lstat(output); err == nil {
			return nil, fmt.Errorf("output file %s already exists, use --force to overwrite", output)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("unable to inspect output file %s: %w", output, err)
		}
	}
	pairs := make([]secretFilePair, 0, len(args))
	for _, arg := range args {
		source, destination, err := resolveSecretPaths(arg, output, sealing)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, secretFilePair{source: source, destination: destination})
	}
	for i, pair := range pairs {
		for j, other := range pairs {
			if sameFilePath(pair.destination, other.source) {
				return nil, fmt.Errorf("output file %s would overwrite input file %s", pair.destination, other.source)
			}
			if j < i && sameFilePath(pair.destination, other.destination) {
				return nil, fmt.Errorf("multiple inputs select the same output file %s", pair.destination)
			}
		}
	}
	return pairs, nil
}

func resolveSecretPaths(arg, output string, sealing bool) (source, destination string, err error) {
	expected := "SealedSecret"
	if sealing {
		expected = "Secret"
	}
	kind, readErr := manifestKind(arg)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return "", "", readErr
	}

	source = arg
	if kind == expected {
		if sealing {
			destination = sealedSibling(arg)
		} else {
			destination = unsealedSibling(arg)
		}
	} else {
		// The argument names the destination. Only a valid companion resource
		// can supply the source, including when this destination is new.
		destination = arg
		if sealing {
			source = unsealedSibling(arg)
		} else {
			source = sealedSibling(arg)
		}
		siblingKind, siblingErr := manifestKind(source)
		if siblingErr != nil {
			if readErr != nil && errors.Is(siblingErr, os.ErrNotExist) {
				return "", "", fmt.Errorf("%w; companion source %s was also not found", readErr, source)
			}
			return "", "", fmt.Errorf("unable to select companion source for %s: %w", arg, siblingErr)
		}
		if siblingKind != expected {
			return "", "", fmt.Errorf("companion source %s must contain a %s", source, expected)
		}
	}
	if output != "" {
		destination = output
	}
	if sameFilePath(source, destination) {
		return "", "", fmt.Errorf("output file %s would overwrite input file %s", destination, source)
	}
	return source, destination, nil
}

func manifestKind(name string) (string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("unable to read file %s: %w", name, err)
	}
	var metadata metav1.TypeMeta
	if err := decodeManifest(data, &metadata); err != nil {
		return "", fmt.Errorf("unable to unmarshal manifest %s: %w", name, err)
	}
	if metadata.APIVersion == "v1" && metadata.Kind == "Secret" {
		return "Secret", nil
	}
	if metadata.APIVersion == "bitnami.com/v1alpha1" && metadata.Kind == "SealedSecret" {
		return "SealedSecret", nil
	}
	return "", fmt.Errorf("file %s must contain a v1 Secret or bitnami.com/v1alpha1 SealedSecret", name)
}

func yamlPathParts(name string) (stem, extension string) {
	extension = filepath.Ext(name)
	if extension != ".yaml" && extension != ".yml" {
		return name, ""
	}
	return strings.TrimSuffix(name, extension), extension
}

func unsealedSibling(name string) string {
	stem, extension := yamlPathParts(name)
	if extension == "" {
		extension = ".yaml"
	}
	return strings.TrimSuffix(stem, ".sealed") + ".unsealed" + extension
}

func sealedSibling(name string) string {
	stem, extension := yamlPathParts(name)
	if strings.HasSuffix(stem, ".unsealed") {
		if extension == "" {
			extension = ".yaml"
		}
		return strings.TrimSuffix(stem, ".unsealed") + extension
	}
	if extension == "" {
		return name + ".yaml"
	}
	// A plainly named Secret is still an input: preserve it rather than
	// replacing it or producing a doubled .yaml extension.
	return stem + ".sealed" + extension
}

func sameFilePath(first, second string) bool {
	firstAbs, firstErr := filepath.Abs(first)
	secondAbs, secondErr := filepath.Abs(second)
	if firstErr == nil && secondErr == nil && firstAbs == secondAbs {
		return true
	}
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	return firstErr == nil && secondErr == nil && os.SameFile(firstInfo, secondInfo)
}
