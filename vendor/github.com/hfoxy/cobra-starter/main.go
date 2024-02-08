package cobrastarter

import (
	"github.com/hfoxy/cobra-starter/cmd"
	"github.com/hfoxy/cobra-starter/logging"
	"github.com/hfoxy/cobra-starter/shutdown"
)

func Run(config cmd.CommandConfig) error {
	go shutdown.Watch()
	defer shutdown.Shutdown()

	logging.Init()

	root, err := cmd.NewRootCommand(config)
	if err != nil {
		logging.Logger().Error("failed to create root command", "error", err)
		return err
	}

	if err = root.Execute(); err != nil {
		return err
	}

	return nil
}
