package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var clientConfig *ClientConfig
var clientConfigErr error

type ClientConfig struct {
	context   string
	config    *clientcmdapi.Config
	clientset *kubernetes.Clientset
	client    *rest.Config
}

func (c *ClientConfig) ClientConfig() (*rest.Config, error) {
	return c.client, nil
}

func (c *ClientConfig) Namespace() (string, bool, error) {
	ctxName := c.config.CurrentContext
	if ctxName == "" {
		return "", false, fmt.Errorf("no current context")
	}

	ctx, ok := c.config.Contexts[ctxName]
	if !ok {
		return "", false, fmt.Errorf("context %s does not exist", ctxName)
	}

	if ctx.Namespace == "" {
		return metav1.NamespaceDefault, true, nil
	}

	return ctx.Namespace, true, nil
}

func getKubeClient() (*ClientConfig, error) {
	if clientConfig != nil || clientConfigErr != nil {
		return clientConfig, clientConfigErr
	}

	clientConfig, clientConfigErr = newKubeClient()
	return clientConfig, clientConfigErr
}

func newKubeClient() (*ClientConfig, error) {
	// Keep supporting semicolon-separated paths while also accepting the
	// platform's standard KUBECONFIG path-list separator.
	var paths []string
	for _, path := range strings.Split(KubeConfig, ";") {
		paths = append(paths, filepath.SplitList(path)...)
	}
	loadingRules := &clientcmd.ClientConfigLoadingRules{Precedence: paths}
	if len(paths) == 1 {
		loadingRules.ExplicitPath = paths[0]
	}
	config, err := loadingRules.Load()
	if err != nil {
		return nil, fmt.Errorf("unable to load kubeconfig file: %w", err)
	}
	if len(paths) > 1 {
		// Keep the application's existing later-file precedence for named
		// entries. client-go's scalar merge still picks the first current context.
		for _, path := range paths {
			if path == "" {
				continue
			}
			fileConfig, err := clientcmd.LoadFromFile(path)
			if os.IsNotExist(err) {
				continue // Like client-go, ignore missing files in a config list.
			}
			if err != nil {
				return nil, fmt.Errorf("unable to load kubeconfig file %s: %w", path, err)
			}
			maps.Copy(config.Clusters, fileConfig.Clusters)
			maps.Copy(config.AuthInfos, fileConfig.AuthInfos)
			maps.Copy(config.Contexts, fileConfig.Contexts)
			maps.Copy(config.Extensions, fileConfig.Extensions)
		}
		if err := clientcmd.ResolveLocalPaths(config); err != nil {
			return nil, fmt.Errorf("unable to resolve kubeconfig paths: %w", err)
		}
	}

	if Context != "" {
		if _, ok := config.Contexts[Context]; !ok {
			return nil, fmt.Errorf("context %s does not exist", Context)
		}

		config.CurrentContext = Context
	}

	c := &ClientConfig{
		context: config.CurrentContext,
		config:  config,
	}

	restConfig, err := clientcmd.NewDefaultClientConfig(*config, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to load kubernetes config: %v", err)
	}

	c.client = restConfig

	result, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes client: %v", err)
	}

	c.clientset = result
	return c, nil
}
