//go:build !windows

package main

import (
	"context"
	"os/exec"
)

// hookCommand runs the operator's -on-change string through the shell, which is
// what anyone typing a command into a flag expects.
func hookCommand(ctx context.Context, line string) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", line)
}
