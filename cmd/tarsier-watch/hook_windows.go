//go:build windows

package main

import (
	"context"
	"os/exec"
	"syscall"
)

// hookCommand runs the operator's -on-change string through cmd.exe.
//
// The command line is handed over raw. Go quotes arguments for the C runtime
// convention, which cmd.exe does not follow, so anything containing quotes or
// redirection comes back to the operator with backslashes in it and does not do
// what they typed. Setting CmdLine is the only way to run their command as
// written.
//
// Note this is cmd syntax, not shell syntax: commands are chained with & rather
// than ; and there is no single-quoting.
func hookCommand(ctx context.Context, line string) *exec.Cmd {
	c := exec.CommandContext(ctx, "cmd")
	c.SysProcAttr = &syscall.SysProcAttr{CmdLine: "/c " + line}
	return c
}
