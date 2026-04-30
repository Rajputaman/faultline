package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/faultline-go/faultline/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var exitErr cli.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		os.Exit(2)
	}
}
