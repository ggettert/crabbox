//go:build darwin || linux

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceOwnerCancellationFromCLIProcessOverProxyAllowsImmediateReuse(t *testing.T) {
	if testing.Short() {
		t.Skip("real OpenSSH proxy CLI regression")
	}
	target, stop := startWorkspaceOwnerRootlessSSHD(t)
	defer stop()
	binary, err := builtCLITestBinary()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	proxy := writeWorkspaceOwnerTCPProxy(t, root, target.Host, target.Port)
	writeWorkspaceOwnerSSHWrapper(t, root)
	list := filepath.Join(root, "list")
	if err := os.WriteFile(list, []byte("#!/bin/sh\nprintf '[]\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	leaseID := fmt.Sprintf("cbx_%012x", uint64(time.Now().UnixNano())&0xffffffffffff)
	config := filepath.Join(root, "config.yaml")
	configBody := fmt.Sprintf(`provider: external
 target: linux
 external:
   capabilities:
     idempotentLeaseId: true
   lifecycle:
     acquire:
       argv: [%q]
     list:
       argv: [%q]
       output: json-name-array
       namePrefix: "cbx-"
     release:
       argv: [%q]
   connection:
     resourceName: "local-proxy"
     cloudId: "local/proxy"
     serverType: "local"
     ssh:
       user: %q
       host: %q
       port: %q
       key: %q
       noControlMaster: true
       proxyCommand: %q
       trustProviderOutput: true
       readyCheck: "true"
   workRoot: %q
 `, "/bin/true", list, "/bin/true", target.User, target.Host, target.Port, target.Key, proxy, filepath.Join(root, "remote-work"))
	configBody = strings.ReplaceAll(configBody, "\n ", "\n")
	if err := os.WriteFile(config, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	environment := append(os.Environ(),
		"HOME="+root,
		"PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"),
		"XDG_CONFIG_HOME="+filepath.Join(root, "config-home"),
		"XDG_STATE_HOME="+filepath.Join(root, "state"),
		"XDG_CACHE_HOME="+filepath.Join(root, "cache"),
		"CRABBOX_CONFIG="+config,
		workspaceOwnerCancellationTraceEnvironment+"=1",
	)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	warmup := exec.CommandContext(ctx, binary, "warmup", "--provider", "external", "--target", "linux", "--lease-id", leaseID, "--slug", "proxy-cancel", "--keep")
	warmup.Env = environment
	if output, err := warmup.CombinedOutput(); err != nil {
		t.Fatalf("warmup err=%v output=%q config=%s", err, output, configBody)
	}
	baseArgs := []string{
		"run", "--provider", "external", "--target", "linux", "--id", leaseID,
		"--no-sync", "--no-hydrate", "--keep",
	}
	stopArgs := []string{"stop", "--provider", "external", "--target", "linux", "--id", leaseID}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		command := exec.CommandContext(cleanupCtx, binary, stopArgs...)
		command.Env = environment
		_ = command.Run()
	})

	args := append(append([]string{}, baseArgs...), "--", "sh", "-lc", `printf 'PROXY_CANCEL_WITNESS pid=%s pgid=%s sid=%s\n' "$$" "$(ps -o pgid= -p $$ | tr -d ' ')" "$(ps -o sid= -p $$ | tr -d ' ')"; printf 'PROXY_CANCEL_STARTED\n'; sleep 30; printf 'PROXY_CANCEL_BAD\n'`)
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = environment
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	witness, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(strings.TrimSpace(witness), "PROXY_CANCEL_WITNESS ") {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("witness line=%q err=%v stderr=%q", witness, err, stderr.String())
	}
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "PROXY_CANCEL_STARTED" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("start line=%q err=%v stderr=%q", line, err, stderr.String())
	}
	child, err := runSSHOutput(ctx, target, `cat "$HOME/.crabbox/workspace-owners/`+workspaceOwnerKey(leaseID)+`.child"`)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	metadata := strings.Split(strings.TrimSpace(child), "\n")
	if len(metadata) != 5 || metadata[0] != metadata[2] || metadata[0] != metadata[3] {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("non-dedicated owner witness=%q workload=%q", child, witness)
	}
	workloadPID := strings.TrimPrefix(strings.Fields(strings.TrimSpace(witness))[1], "pid=")
	if workloadPID == metadata[0] {
		t.Fatalf("nested workload shell unexpectedly reused owner registrar PID: workload=%q owner=%q", witness, metadata)
	}
	t.Logf("workload witness=%q owner witness=%q", strings.TrimSpace(witness), metadata)
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	remaining, readErr := reader.ReadString('\n')
	waitErr := command.Wait()
	if readErr == nil && strings.Contains(remaining, "PROXY_CANCEL_BAD") {
		t.Fatalf("remote workload continued after cancellation: %q", remaining)
	}
	exit := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exit = exitErr.ExitCode()
		} else {
			t.Fatal(waitErr)
		}
	}
	for _, want := range []string{
		"workspace owner cancellation trace transport_return cause=canceled raw_error=present",
		"workspace owner cancellation trace action=cancel_child response=CANCELED error=none",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("cancel trace missing %q: %s", want, stderr.String())
		}
	}
	if exit != 1 || !strings.Contains(stderr.String(), "workspace owner released") {
		t.Fatalf("cancel exit=%d stderr=%q", exit, stderr.String())
	}

	nextArgs := append(append([]string{}, baseArgs...), "--", "printf", "PROXY_NEXT_OK\\n")
	next := exec.CommandContext(ctx, binary, nextArgs...)
	next.Env = environment
	nextOutput, err := next.CombinedOutput()
	if err != nil || !strings.Contains(string(nextOutput), "PROXY_NEXT_OK") {
		t.Fatalf("immediate reuse err=%v output=%q", err, nextOutput)
	}
}

func writeWorkspaceOwnerSSHWrapper(t *testing.T, root string) {
	t.Helper()
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal(err)
	}
	wrapper := "#!/bin/sh\nexec " + shellQuote(ssh) + " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \"$@\"\n"
	if err := os.WriteFile(filepath.Join(root, "ssh"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeWorkspaceOwnerTCPProxy(t *testing.T, root, host, port string) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the local proxy transport fixture")
	}
	path := filepath.Join(root, "ssm-proxy.py")
	script := `#!` + python + `
import os
import socket
import sys
import threading

connection = socket.create_connection((sys.argv[1], int(sys.argv[2])))

def upload():
    try:
        while True:
            data = os.read(0, 65536)
            if not data:
                break
            connection.sendall(data)
    finally:
        try:
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass

thread = threading.Thread(target=upload, daemon=True)
thread.start()
while True:
    data = connection.recv(65536)
    if not data:
        break
    os.write(1, data)
thread.join(timeout=1)
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return strings.Join([]string{shellQuote(python), shellQuote(path), shellQuote(host), shellQuote(port)}, " ")
}

func TestWorkspaceOwnerCancellationTraceCoversNilTransportError(t *testing.T) {
	t.Setenv(workspaceOwnerCancellationTraceEnvironment, "1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	target := SSHTarget{TargetOS: targetLinux}
	var trace bytes.Buffer
	transport := sshTransportPreparation{runOverride: func(context.Context, *SSHTarget, string, string, io.Writer, io.Writer) error {
		return nil
	}}
	err := transport.execute(ctx, &target, sshCommandLimit{}, "10", "1", io.Discard, &trace)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("normalized transport error=%v", err)
	}
	cancelCalls := 0
	owner := &workspaceOwner{
		target: target,
		key:    "cancel-nil-transport",
		token:  strings.Repeat("a", 64),
		ttl:    time.Minute,
		transport: workspaceOwnerTransportFunc(func(_ context.Context, request workspaceOwnerRemoteRequest) (string, error) {
			if request.Action != workspaceOwnerCancel {
				t.Fatalf("unexpected owner action %s", request.Action)
			}
			cancelCalls++
			return "CANCELED", nil
		}),
	}
	err = finishSSHWorkspaceOwnerCancellation(ctx, target, owner, err, &trace)
	if !errors.Is(err, context.Canceled) || cancelCalls != 1 {
		t.Fatalf("cancel finalizer error=%v calls=%d", err, cancelCalls)
	}
	for _, want := range []string{
		"workspace owner cancellation trace transport_return cause=canceled raw_error=none",
		"workspace owner cancellation trace action=cancel_child response=CANCELED error=none",
	} {
		if !strings.Contains(trace.String(), want) {
			t.Fatalf("trace missing %q: %s", want, trace.String())
		}
	}
}
