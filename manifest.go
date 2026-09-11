package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// Each input file maps to one output file, so never silently discard resources
// after the first YAML document.
func decodeManifest(data []byte, resource interface{}) error {
	decoder := kubeyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var document json.RawMessage
	for {
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("input contains no resource")
			}
			return err
		}
		if len(document) > 0 && string(document) != "null" {
			break
		}
	}
	if err := json.Unmarshal(document, resource); err != nil {
		return err
	}
	for {
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(extra) > 0 && string(extra) != "null" {
			return fmt.Errorf("multiple resources in one input file are not supported")
		}
	}
}
