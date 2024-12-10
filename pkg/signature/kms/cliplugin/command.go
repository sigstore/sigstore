package cliplugin

import (
	"context"
	"io"
	"os/exec"
)

type command interface {
	Output() ([]byte, error)
}

type makeCommandFunc func(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command

func makeCommand(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stderr = stderr
	return cmd
}

type commandExitError interface {
	ExitCode() int
	Error() string
}
