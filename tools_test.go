package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
)

type certificateTestTransport func(*http.Request) (*http.Response, error)

func (f certificateTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type certificateTestBody struct {
	io.Reader
	closed bool
}

func (b *certificateTestBody) Close() error {
	b.closed = true
	return nil
}

func TestGetPublicKeyClosesCertificateOnParseError(t *testing.T) {
	body := &certificateTestBody{Reader: strings.NewReader("invalid certificate")}
	transport := certificateTestTransport(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/v1/cert.pem") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/x-pem-file"}},
				Body:       body,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"apiVersion":"v1","kind":"Service",` +
				`"spec":{"ports":[{"name":"http","port":8080}]}}`)),
		}, nil
	})
	oldClient, oldErr := clientConfig, clientConfigErr
	clientConfig = &ClientConfig{client: &rest.Config{Host: "https://example.invalid", Transport: transport}}
	clientConfigErr = nil
	t.Cleanup(func() { clientConfig, clientConfigErr = oldClient, oldErr })
	if _, err := getPublicKey(context.Background()); err == nil {
		t.Fatal("expected invalid certificate to fail")
	}
	if !body.closed {
		t.Fatal("certificate response body was not closed")
	}
}
