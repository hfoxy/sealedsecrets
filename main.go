package main

import (
	"fmt"
	cobrastarter "github.com/hfoxy/cobra-starter"
	"github.com/hfoxy/cobra-starter/cmd"
	"github.com/hfoxy/cobra-starter/flags"
	"github.com/hfoxy/cobra-starter/logging"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

func main() {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		println(fmt.Sprintf("unable to load .env: %v", err))
		os.Exit(1)
	}

	logging.LogOutputs = "stdout:text"

	err := cobrastarter.Run(cmd.CommandConfig{
		ConfigFileName: "sealedsecrets",
		EnvPrefix:      "",
		BaseCommand: &cobra.Command{
			Use:   "sealedsecrets",
			Short: "tool for working with sealed secrets",
		},
		DisableDefaultFlags: true,
		RootFlags: func(cmd *cobra.Command) error {
			cmd.PersistentFlags().BoolVarP(&flags.DebugEnabled, "debug", "d", flags.DebugEnabled, "Enable debug logging")

			kubeconfig := os.Getenv("KUBECONFIG")
			if kubeconfig == "" {
				kubeconfig = filepath.Join(getHome(), ".kube", "config")
			}
			cmd.PersistentFlags().StringVar(&KubeConfig, "kubeconfig", kubeconfig, "Kubeconfig file or path list, defaults to KUBECONFIG or ~/.kube/config")
			cmd.PersistentFlags().StringVarP(&Context, "context", "c", Context, "Kubernetes context, defaults to current context")
			// TODO: add autocompletion that fetches the current kube contexts

			cmd.PersistentFlags().BoolVarP(&Force, "force", "F", Force, "force overwrite of existing files")
			cmd.PersistentFlags().StringVarP(&Namespace, "namespace", "n", Namespace, "namespace, will attempt to find in file if not specified")
			cmd.PersistentFlags().StringVar(&ControllerName, "controller-name", ControllerName, "name of the sealed secrets controller")
			cmd.PersistentFlags().StringVar(&ControllerNamespace, "controller-namespace", ControllerNamespace, "namespace where the sealed secrets controller lives")
			return nil
		},
		Commands: []cmd.CommandAdder{
			unsealCommand,
			sealCommand,
		},
	})

	if err != nil {
		println(fmt.Sprintf("error: %v", err))
		os.Exit(1)
	}
}

func unsealCommand(rootCmd *cobra.Command) (*cobra.Command, error) {
	c := &cobra.Command{
		Use:        "unseal",
		Short:      "unseal a sealed secret",
		Long:       "Unseal a SealedSecret into its .unsealed.yaml (or .yml) sibling. You can also name the unsealed destination to select its sealed sibling as the source. Existing outputs require --force.",
		Args:       cobra.MinimumNArgs(1),
		ArgAliases: []string{"secret_path"},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return []string{toComplete}, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: Unseal,
	}

	c.PersistentFlags().BoolVarP(&Decode, "decode", "D", Decode, "decode UTF-8 values into stringData, preserving binary values in data")
	c.PersistentFlags().StringVarP(&OutputFile, "output", "o", OutputFile, "output file, overrides the inferred unsealed destination")
	return c, nil
}

func sealCommand(rootCmd *cobra.Command) (*cobra.Command, error) {
	c := &cobra.Command{
		Use:        "seal",
		Short:      "seal a secret",
		Long:       "Seal a Secret into its sealed sibling. If the path contains a SealedSecret, use its .unsealed.yaml (or .yml) sibling as the source and update the named path. An unmarked Secret such as secrets.yaml is written to secrets.sealed.yaml. Existing outputs require --force.",
		Args:       cobra.MinimumNArgs(1),
		ArgAliases: []string{"secret_path"},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return []string{toComplete}, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: Seal,
	}

	c.PersistentFlags().BoolVarP(&Reseal, "reseal", "r", Reseal, "reseal the whole secret, not just the updated parts")
	c.PersistentFlags().BoolVarP(&KeepTemplate, "keep-template", "t", KeepTemplate, "keep the template")
	c.PersistentFlags().StringVarP(&OutputFile, "output", "o", OutputFile, "output file, overrides the inferred sealed destination")
	c.PersistentFlags().VarP(&Scope, "scope", "s", "sealing scope (strict, namespace-wide, cluster-wide)")

	return c, nil
}
