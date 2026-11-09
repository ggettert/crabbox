//go:build darwin || linux

package cli

import (
	"bytes"
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
case "` + sshMode + `" in
  exit) exit 0 ;;
  fail) exit 255 ;;
esac
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

func TestProxyReadinessRetriesTransientSSHFailureAfterConfirmedCleanup(t *testing.T) {
	callsPath := filepath.Join(t.TempDir(), "proxy-calls")
	target, tempDir := installProxyStatusFakeSSH(t, `
status=$CRABBOX_INTERNAL_PROXY_STATUS_DIR
printf call >> "`+callsPath+`"
printf started > "$status/started"
trap 'printf "ok\n" > "$status/.result"; mv "$status/.result" "$status/result"; exit 0' TERM
while :; do sleep 1; done
`, "fail")
	var progress bytes.Buffer
	err := waitForSSHReady(t.Context(), &target, &progress, "bootstrap", 700*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out waiting for SSH") {
		t.Fatalf("readiness error=%v progress=%s", err, progress.String())
	}
	calls, readErr := os.ReadFile(callsPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(calls) < 2 {
		t.Fatalf("proxy calls=%d, want retry after confirmed cleanup", len(calls))
	}
	if strings.Contains(err.Error(), "class=lifecycle_cleanup") {
		t.Fatalf("successful cleanup poisoned readiness retry: %v", err)
	}
	assertProxyStatusTempClean(t, tempDir)
}

func TestProxyReadinessStartedHelperWithoutReceiptStopsRetry(t *testing.T) {
	previousGrace := proxyCommandStatusGrace
	proxyCommandStatusGrace = 50 * time.Millisecond
	t.Cleanup(func() { proxyCommandStatusGrace = previousGrace })
	callsPath := filepath.Join(t.TempDir(), "proxy-calls")
	target, tempDir := installProxyStatusFakeSSH(t, `
status=$CRABBOX_INTERNAL_PROXY_STATUS_DIR
printf call >> "`+callsPath+`"
printf started > "$status/started"
exit 0
`, "fail")
	var progress bytes.Buffer
	err := waitForSSHReady(t.Context(), &target, &progress, "bootstrap", time.Second)
	if err == nil || !strings.Contains(err.Error(), "class=lifecycle_cleanup") || !strings.Contains(err.Error(), "code=result_missing") {
		t.Fatalf("readiness error=%v progress=%s", err, progress.String())
	}
	calls, readErr := os.ReadFile(callsPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(calls) != "call" {
		t.Fatalf("proxy calls=%q, want exactly one", calls)
	}
	if strings.Contains(err.Error(), tempDir) {
		t.Fatalf("readiness error leaked private status path: %v", err)
	}
	assertProxyStatusTempClean(t, tempDir)
}

func TestWindowsBootstrapStabilityCleanupFailureStopsRetry(t *testing.T) {
	eventsPath := filepath.Join(t.TempDir(), "ssm-events")
	target, tempDir := installProxyStatusFakeSSH(t, `
status=$CRABBOX_INTERNAL_PROXY_STATUS_DIR
printf 'StartSession\n' >> "`+eventsPath+`"
printf started > "$status/started"
trap 'printf "TerminateSession\n" >> "`+eventsPath+`"; printf "error: terminate owned SSM session: AWS API error AccessDeniedException private-detail\n" > "$status/.result"; mv "$status/.result" "$status/result"; exit 0' TERM
while :; do sleep 1; done
`, "fail")
	target.TargetOS = targetWindows
	target.WindowsMode = windowsModeNormal
	var progress bytes.Buffer
	err := waitForWindowsSSHStability(t.Context(), &target, &progress, time.Now().Add(time.Second), time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "class=lifecycle_cleanup") || !strings.Contains(err.Error(), "code=AccessDeniedException") {
		t.Fatalf("stability error=%v progress=%s", err, progress.String())
	}
	events, readErr := os.ReadFile(eventsPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(events) != "StartSession\nTerminateSession\n" {
		t.Fatalf("SSM events=%q, want one start and one failed terminate", events)
	}
	if strings.Contains(err.Error(), "private-detail") || strings.Contains(err.Error(), tempDir) {
		t.Fatalf("stability error leaked private detail: %v", err)
	}
	assertProxyStatusTempClean(t, tempDir)
}

func TestProxyCommandStatusInvalidResultsUseSafeFatalClasses(t *testing.T) {
	for _, test := range []struct {
		name string
		code string
		make func(t *testing.T, path string)
	}{
		{
			name: "invalid",
			code: "invalid_result",
			make: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("private invalid lifecycle content"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unreadable",
			code: "result_unreadable",
			make: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			status := &proxyCommandStatus{}
			command := exec.Command("true")
			if err := status.prepare(command); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(status.dir, "started"), []byte("started"), 0o600); err != nil {
				t.Fatal(err)
			}
			test.make(t, filepath.Join(status.dir, "result"))
			err := status.wait(false)
			var statusErr *proxyCommandStatusError
			if !errors.As(err, &statusErr) || statusErr.class != proxyCommandFailureUnknownOutcome || statusErr.code != test.code || !statusErr.readinessFatal() {
				t.Fatalf("status error=%v", err)
			}
			if strings.Contains(err.Error(), status.dir) || strings.Contains(err.Error(), "private") {
				t.Fatalf("status error leaked private detail: %v", err)
			}
			if err := status.cleanup(); err != nil {
				t.Fatal(err)
			}
		})
	}
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
	err := status.wait(true)
	var statusErr *proxyCommandStatusError
	if !errors.As(err, &statusErr) || statusErr.class != proxyCommandFailureUnknownOutcome || statusErr.code != "missing_start_marker" || !statusErr.readinessFatal() {
		t.Fatalf("normal completion error=%v", err)
	}
	if err := status.cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyCommandStatusErrorUsesOnlySafeClasses(t *testing.T) {
	for _, test := range []struct {
		result string
		class  proxyCommandFailureClass
		code   string
		fatal  bool
	}{
		{result: "terminate owned SSM session: AWS API error AccessDeniedException private-detail", class: proxyCommandFailureLifecycleCleanup, code: "AccessDeniedException", fatal: true},
		{result: "terminate owned SSM session: context deadline exceeded private-detail", class: proxyCommandFailureLifecycleCleanup, code: "deadline_exceeded", fatal: true},
		{result: "start SSM session: AWS API error AccessDeniedException\nSSM session start outcome is unknown because no session ID was returned", class: proxyCommandFailurePermissionDenied, code: "AccessDeniedException", fatal: true},
		{result: "SSM session start outcome is unknown because no session ID was returned", class: proxyCommandFailureUnknownOutcome, fatal: true},
		{result: "private arbitrary helper failure", class: proxyCommandFailureLifecycle},
	} {
		err := classifyProxyCommandStatusError(test.result)
		if err.class != test.class || err.code != test.code || err.readinessFatal() != test.fatal {
			t.Errorf("%q: got class=%q code=%q fatal=%t", test.result, err.class, err.code, err.readinessFatal())
		}
		if strings.Contains(err.Error(), "private") {
			t.Errorf("unsafe lifecycle detail retained: %v", err)
		}
	}
}
