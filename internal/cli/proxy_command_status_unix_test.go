//go:build darwin || linux

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installProxyStatusFakeSSH(t *testing.T, proxyBody, sshMode string) (SSHTarget, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(dir, "tmp"))
	if err := os.Mkdir(filepath.Join(dir, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	proxy := filepath.Join(dir, "proxy")
	if err := os.WriteFile(proxy, []byte("#!/bin/sh\nset -eu\n"+proxyBody+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(dir, "ssh")
	sshScript := `#!/bin/sh
set -eu
proxy=
for arg in "$@"; do
  case "$arg" in ProxyCommand=*) proxy=${arg#ProxyCommand=} ;; esac
done
[ -n "$proxy" ]
sh -c "exec $proxy" &
proxy_pid=$!
while [ ! -f "$CRABBOX_INTERNAL_PROXY_STATUS_DIR/started" ]; do sleep 0.01; done
if [ "` + sshMode + `" = exit ]; then
  exit 0
fi
wait "$proxy_pid"
`
	if err := os.WriteFile(ssh, []byte(sshScript), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	target := SSHTarget{
		User: "ubuntu", Host: "i-0123456789abcdef0", Port: "22", TargetOS: targetLinux,
		NoControlMaster: true, DisableHostKeyChecking: true,
		ProxyCommand: filepath.ToSlash(proxy), ProxyCommandStatus: true,
	}
	return target, filepath.Join(dir, "tmp")
}

func assertProxyStatusTempClean(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("proxy status temp directory leaked: %v", entries)
	}
}

func TestOwnedSSHTransportSurfacesProxyCleanupFailureAfterSSHExitZero(t *testing.T) {
	target, tempDir := installProxyStatusFakeSSH(t, `
status=$CRABBOX_INTERNAL_PROXY_STATUS_DIR
printf started > "$status/started"
trap 'printf "error: terminate owned SSM session: AWS API error AccessDeniedException\n" > "$status/.result"; mv "$status/.result" "$status/result"; exit 0' TERM
while :; do sleep 1; done
`, "exit")
	err := executePreparedSSH(t.Context(), &target, "true", nil, 0, sshCommandLimit{}, "10", "1", io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Fatalf("error=%v", err)
	}
	assertProxyStatusTempClean(t, tempDir)
}

func TestOwnedSSHTransportCancellationAllowsProxyCleanupBeforeForceKill(t *testing.T) {
	target, tempDir := installProxyStatusFakeSSH(t, `
status=$CRABBOX_INTERNAL_PROXY_STATUS_DIR
printf started > "$status/started"
trap 'printf "ok\n" > "$status/.result"; mv "$status/.result" "$status/result"; exit 0' TERM
while :; do sleep 1; done
`, "wait")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- executePreparedSSH(ctx, &target, "sleep 60", nil, 0, sshCommandLimit{}, "10", "1", io.Discard, io.Discard)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not complete within the graceful cleanup bound")
	}
	assertProxyStatusTempClean(t, tempDir)
}

func TestOwnedSSHTransportForceKillsProxyAfterCleanupGraceExpires(t *testing.T) {
	previousGrace := proxyCommandStatusGrace
	proxyCommandStatusGrace = 100 * time.Millisecond
	t.Cleanup(func() { proxyCommandStatusGrace = previousGrace })
	target, tempDir := installProxyStatusFakeSSH(t, `
status=$CRABBOX_INTERNAL_PROXY_STATUS_DIR
printf started > "$status/started"
trap '' TERM
while :; do sleep 1; done
`, "exit")
	started := time.Now()
	err := executePreparedSSH(t.Context(), &target, "true", nil, 0, sshCommandLimit{}, "10", "1", io.Discard, io.Discard)
	duration := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "grace period expired") {
		t.Fatalf("error=%v", err)
	}
	if duration < proxyCommandStatusGrace || duration > proxyCommandStatusGrace+2*time.Second {
		t.Fatalf("cleanup duration=%s", duration)
	}
	assertProxyStatusTempClean(t, tempDir)
}

func TestOwnedSSHTransportWaitsForDelayedCleanupReceipt(t *testing.T) {
	previousGrace := proxyCommandStatusGrace
	proxyCommandStatusGrace = 500 * time.Millisecond
	t.Cleanup(func() { proxyCommandStatusGrace = previousGrace })
	target, tempDir := installProxyStatusFakeSSH(t, `
status=$CRABBOX_INTERNAL_PROXY_STATUS_DIR
printf started > "$status/started"
trap 'sleep 0.15; printf "ok\n" > "$status/.result"; mv "$status/.result" "$status/result"; exit 0' TERM
while :; do sleep 1; done
`, "exit")
	started := time.Now()
	if err := executePreparedSSH(t.Context(), &target, "true", nil, 0, sshCommandLimit{}, "10", "1", io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	duration := time.Since(started)
	if duration < 150*time.Millisecond || duration >= proxyCommandStatusGrace {
		t.Fatalf("cleanup duration=%s", duration)
	}
	assertProxyStatusTempClean(t, tempDir)
}

func TestConcurrentOwnedSSHTransportsUseSeparateStatusDirectories(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "status-dirs")
	target, tempDir := installProxyStatusFakeSSH(t, `
status=$CRABBOX_INTERNAL_PROXY_STATUS_DIR
printf '%s\n' "$status" >> "`+logPath+`"
printf started > "$status/started"
trap 'printf "ok\n" > "$status/.result"; mv "$status/.result" "$status/result"; exit 0' TERM
while :; do sleep 1; done
`, "exit")
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			errs <- executePreparedSSH(t.Context(), &target, "true", nil, 0, sshCommandLimit{}, "10", "1", io.Discard, io.Discard)
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(data))
	if len(lines) != 2 || lines[0] == lines[1] {
		t.Fatalf("status directories=%q", lines)
	}
	assertProxyStatusTempClean(t, tempDir)
}

func TestProxyCommandStatusRequiresReceiptOnlyForNormalCompletion(t *testing.T) {
	status := &proxyCommandStatus{}
	command := exec.Command("true")
	if err := status.prepare(command); err != nil {
		t.Fatal(err)
	}
	if err := status.wait(false); err != nil {
		t.Fatalf("early cancellation without helper start: %v", err)
	}
	if err := status.wait(true); err == nil || !strings.Contains(err.Error(), "without reporting") {
		t.Fatalf("normal completion error=%v", err)
	}
	if err := status.cleanup(); err != nil {
		t.Fatal(err)
	}
}
