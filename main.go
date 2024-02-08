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

			cmd.PersistentFlags().StringVar(&KubeConfig, "kubeconfig", filepath.Join(getHome(), ".kube", "config"), "Kubernetes context, defaults to current context")
			cmd.PersistentFlags().StringVarP(&Context, "context", "c", Context, "Kubernetes context, defaults to current context")
			// TODO: add autocompletion that fetches the current kube contexts

			cmd.PersistentFlags().BoolVarP(&Force, "force", "F", Force, "force overwrite of existing files")
			cmd.PersistentFlags().StringVarP(&Namespace, "namespace", "n", Namespace, "namespace, will attempt to find in file if not specified")
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
		Args:       cobra.MinimumNArgs(1),
		ArgAliases: []string{"secret_path"},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return []string{toComplete}, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: Unseal,
	}

	c.PersistentFlags().BoolVarP(&Decode, "decode", "D", Decode, "force overwrite of existing files")
	c.PersistentFlags().StringVarP(&OutputFile, "output", "o", OutputFile, "output file, defaults to modified input file if input ends with .yaml or no extension is provided")
	return c, nil
}

func sealCommand(rootCmd *cobra.Command) (*cobra.Command, error) {
	c := &cobra.Command{
		Use:        "seal",
		Short:      "seal a sealed secret",
		Args:       cobra.MinimumNArgs(1),
		ArgAliases: []string{"secret_path"},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return []string{toComplete}, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: Seal,
	}

	c.PersistentFlags().BoolVarP(&Reseal, "reseal", "r", Reseal, "reseal the whole secret, not just the updated parts")
	c.PersistentFlags().BoolVarP(&KeepTemplate, "keep-template", "t", KeepTemplate, "keep the template")
	c.PersistentFlags().StringVarP(&OutputFile, "output", "o", OutputFile, "output file, defaults to modified input file if input ends with .unsealed.yaml or no extension is provided")
	c.PersistentFlags().VarP(&Scope, "scope", "s", "sealing scope (namespace, cluster, strict)")
	c.PersistentFlags().StringVar(&ControllerName, "controller-name", ControllerName, "name of the sealed secrets controller")
	c.PersistentFlags().StringVar(&ControllerNamespace, "controller-namespace", ControllerNamespace, "namespace where the sealed secrets controller lives")

	return c, nil
}
