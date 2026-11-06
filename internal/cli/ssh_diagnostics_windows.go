package cli

import (
	"io"
	"os/exec"
)

func runSSHCommandWithLocalDiagnostics(cmd *exec.Cmd, stdout, stderr io.Writer) (bool, error) {
	return false, runSSHCommand(cmd, stdout, stderr)
}

func runSSHCommandWithLocalDiagnosticsRunner(cmd *exec.Cmd, stdout, stderr io.Writer, run func(*exec.Cmd, io.Writer, io.Writer) error) (bool, error) {
	return false, run(cmd, stdout, stderr)
}
