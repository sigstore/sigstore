//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cliplugin implements the plugin functionality.
package cliplugin

import (
	"context"
	"io"
	"os/exec"
)

// Here we have convenient interfaces that allow us to monkeypatch for unit-testing purposes.

// command is an interface for os/exec.Command.
type command interface {
	Output() ([]byte, error)
}

// makeCommandFunc is function for creating an os/exec.Command.
type makeCommandFunc func(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command

// makeCommand makes a os/exec.Command with CommandContext().
func makeCommand(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stderr = stderr
	return cmd
}

// commandExitError is an interface for os/exec.ExitError.
type commandExitError interface {
	ExitCode() int
	Error() string
}
