package main

import (
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"log"
	"os"
	"sigs.k8s.io/yaml"
	"strings"
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

type Config struct {
	Kind           string                    `json:"kind,omitempty"`
	APIVersion     string                    `json:"apiVersion,omitempty"`
	Preferences    clientcmdapi.Preferences  `json:"preferences"`
	Clusters       []*NamedCluster           `json:"clusters"`
	AuthInfos      []*NamedAuthInfo          `json:"users"`
	Contexts       []*NamedContext           `json:"contexts"`
	CurrentContext string                    `json:"current-context"`
	Extensions     map[string]runtime.Object `json:"extensions,omitempty"`
}

type NamedCluster struct {
	Name    string                `json:"name"`
	Cluster *clientcmdapi.Cluster `json:"cluster"`
}

type NamedContext struct {
	Name    string                `json:"name"`
	Context *clientcmdapi.Context `json:"context"`
}

type NamedAuthInfo struct {
	Name     string                 `json:"name"`
	AuthInfo *clientcmdapi.AuthInfo `json:"user"`
}

func getKubeClient() (*ClientConfig, error) {
	if clientConfig != nil || clientConfigErr != nil {
		return clientConfig, clientConfigErr
	}

	clientConfig, clientConfigErr = newKubeClient()
	return clientConfig, clientConfigErr
}

func newKubeClient() (*ClientConfig, error) {
	var restConfig *rest.Config
	var err error

	split := strings.Split(KubeConfig, ";")

	first := true
	config := &clientcmdapi.Config{}
	for _, path := range split {
		var data []byte
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("unable to read kubeconfig file: %v", err)
		}

		c := &Config{}
		err = yaml.Unmarshal(data, c)
		if err != nil {
			log.Printf("%s", string(data))
			return nil, fmt.Errorf("unable to unmarshal kubeconfig file: %v", err)
		}

		if first {
			kconfig := clientcmdapi.NewConfig()
			kconfig.Kind = c.Kind
			kconfig.APIVersion = c.APIVersion
			kconfig.CurrentContext = c.CurrentContext
			kconfig.Preferences = c.Preferences
			kconfig.Extensions = c.Extensions

			for _, v := range c.Clusters {
				kconfig.Clusters[v.Name] = v.Cluster
			}

			for _, v := range c.AuthInfos {
				kconfig.AuthInfos[v.Name] = v.AuthInfo
			}

			for _, v := range c.Contexts {
				kconfig.Contexts[v.Name] = v.Context
			}

			config = kconfig
			first = false
		} else {
			for _, v := range c.Clusters {
				config.Clusters[v.Name] = v.Cluster
			}

			for _, v := range c.AuthInfos {
				config.AuthInfos[v.Name] = v.AuthInfo
			}

			for _, v := range c.Contexts {
				config.Contexts[v.Name] = v.Context
			}

			for k, v := range c.Extensions {
				config.Extensions[k] = v
			}

			config.CurrentContext = c.CurrentContext
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

	restConfig, err = clientcmd.NewDefaultClientConfig(*config, &clientcmd.ConfigOverrides{}).ClientConfig()
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
