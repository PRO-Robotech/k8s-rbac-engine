package main

import (
	"os"

	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/component-base/cli"

	"k8s-rbac-engine/internal/app"
)

func main() {
	ctx := genericapiserver.SetupSignalContext()
	opts := app.NewServerOptions(os.Stdout, os.Stderr)
	command := app.NewCommandStartServer(ctx, opts)
	code := cli.Run(command)
	os.Exit(code)
}
