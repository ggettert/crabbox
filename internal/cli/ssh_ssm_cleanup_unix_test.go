//go:build darwin || linux

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type ssmCleanupFixture struct {
	dir       string
	proxy     string
	startedAt map[int]string
}

func newSSMCleanupFixture(t *testing.T, mode string) *ssmCleanupFixture {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the local SSM transport fixture")
	}
	dir := t.TempDir()
	program := filepath.Join(dir, "transport.py")
	script := `#!` + python + `
import glob
import os
import signal
import socket
import subprocess
import sys
import time

role = os.path.basename(sys.argv[0])
root = os.environ["CRABBOX_SSM_FIXTURE"]

def record(kind):
    path = os.path.join(root, "%s-%d.pid" % (kind, os.getpid()))
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))

if role == "session-manager-plugin":
    record("plugin")
    while True:
        signal.pause()

if role == "aws":
    record("aws")
    with open(os.path.join(root, "aws.calls"), "a", encoding="utf-8") as handle:
        handle.write(" ".join(sys.argv[1:]) + "\n")
    plugin = subprocess.Popen([os.path.join(root, "session-manager-plugin")])
    plugin.wait()
    raise SystemExit(plugin.returncode)

if role != "ssh":
    raise SystemExit("unexpected fixture role: " + role)

record("ssh")
args = sys.argv[1:]
config = ""
proxy = ""
forward = ""
for index, arg in enumerate(args):
    if arg == "-F" and index + 1 < len(args):
        config = args[index + 1]
    if arg == "-L" and index + 1 < len(args):
        forward = args[index + 1]
    if arg.startswith("ProxyCommand="):
        proxy = arg[len("ProxyCommand="):]
def proxy_from_config(path):
    selected = ""
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped.lower().startswith("include "):
                included = stripped[len("include "):].strip().strip('"')
                nested = proxy_from_config(included)
                if nested:
                    selected = nested
            if stripped.lower().startswith("proxycommand "):
                selected = stripped[len("proxycommand "):]
    return selected

if config:
    configured = proxy_from_config(config)
    if configured:
        proxy = configured
if "-G" in args:
    if not proxy:
        raise SystemExit("missing ProxyCommand")
    print("hostname i-0123456789abcdef0")
    print("identitiesonly yes")
    print("identityfile none")
    print("identityagent none")
    print("proxycommand " + proxy)
    raise SystemExit(0)
if not proxy:
    raise SystemExit("missing ProxyCommand")
subprocess.Popen(proxy, shell=True)
deadline = time.monotonic() + 5
while not glob.glob(os.path.join(root, "plugin-*.pid")):
    if time.monotonic() >= deadline:
        raise SystemExit("proxy plugin did not start")
    time.sleep(0.01)
with open(os.path.join(root, "ssh.ready"), "w", encoding="utf-8") as handle:
    handle.write(str(os.getpid()))
mode = os.environ["CRABBOX_SSM_MODE"]
if mode == "normal":
    raise SystemExit(0)
if mode == "release":
    while not os.path.exists(os.path.join(root, "allow-exit")):
        time.sleep(0.001)
    raise SystemExit(0)
if mode == "blocked-output":
    print("blocked transport output", flush=True)
if mode == "tunnel":
    port = int(forward.split(":")[1])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen()
    with open(os.path.join(root, "tunnel.ready"), "w", encoding="utf-8") as handle:
        handle.write(str(port))
    while True:
        connection, _ = listener.accept()
        connection.close()
while True:
    signal.pause()
`
	if err := os.WriteFile(program, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ssh", "aws", "session-manager-plugin"} {
		if err := os.Symlink(program, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CRABBOX_SSM_FIXTURE", dir)
	t.Setenv("CRABBOX_SSM_MODE", mode)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	fixture := &ssmCleanupFixture{
		dir:       dir,
		proxy:     shellQuote(filepath.Join(dir, "aws")) + " ssm start-session --target i-0123456789abcdef0 --document-name AWS-StartSSHSession --parameters portNumber=%p --region us-test-1",
		startedAt: map[int]string{},
	}
	t.Cleanup(func() {
		for _, pid := range fixture.pids(t) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	return fixture
}

func (f *ssmCleanupFixture) target() SSHTarget {
	return SSHTarget{
		User: "ubuntu", Host: "i-0123456789abcdef0", Port: "22", TargetOS: targetLinux,
		NoControlMaster: true, DisableHostKeyChecking: true, ProxyCommand: f.proxy,
	}
}

func (f *ssmCleanupFixture) configProxyTarget(t *testing.T) SSHTarget {
	t.Helper()
	config := strings.Join([]string{
		"Host provider-alias",
		"  HostName i-0123456789abcdef0",
		"  User ubuntu",
		"  Port 22",
		"  IdentitiesOnly yes",
		"  IdentityFile none",
		"  IdentityAgent none",
		"  ProxyCommand " + f.proxy,
		"",
	}, "\n")
	path := filepath.Join(f.dir, "provider-ssh-config")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return SSHTarget{
		User: "ubuntu", Host: "provider-alias", Port: "22", TargetOS: targetLinux,
		NoControlMaster: true, DisableHostKeyChecking: true,
		SSHConfigProxy: true, SSHConfigFile: path, SSHConfigData: []byte(config),
	}
}

func (f *ssmCleanupFixture) pids(t *testing.T) []int {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(f.dir, "*.pid"))
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			t.Fatalf("invalid fixture PID %q in %s", data, path)
		}
		pids = append(pids, pid)
	}
	return pids
}

func (f *ssmCleanupFixture) captureLiveIdentities(t *testing.T) []int {
	t.Helper()
	var live []int
	for _, pid := range f.pids(t) {
		snapshot, err := inspectProcessSnapshot(pid)
		if err != nil || snapshot.exited {
			continue
		}
		f.startedAt[pid] = snapshot.started
		live = append(live, pid)
	}
	return live
}

func (f *ssmCleanupFixture) assertAllGone(t *testing.T) {
	t.Helper()
	pids := f.pids(t)
	if len(pids) < 3 {
		t.Fatalf("fixture did not start the SSH, AWS CLI, and plugin process tree: pids=%v", pids)
	}
	f.captureLiveIdentities(t)
	boundaryEventually(t, "SSM transport process tree reaped", func() bool {
		for _, pid := range pids {
			snapshot, err := inspectProcessSnapshot(pid)
			if err != nil || snapshot.exited {
				continue
			}
			if started := f.startedAt[pid]; started != "" && started != snapshot.started {
				continue
			}
			return false
		}
		return true
	})
	data, err := os.ReadFile(filepath.Join(f.dir, "aws.calls"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ssm start-session --target i-0123456789abcdef0") {
		t.Fatalf("fake AWS CLI did not receive the SSM start-session route: %q", data)
	}
}

func awaitSSMFixtureFile(t *testing.T, path string, done <-chan error) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("transport exited before fixture readiness: %v", err)
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", filepath.Base(path))
		case <-ticker.C:
		}
	}
}

func TestSSMProxyCommandNormalExitReapsTransportTree(t *testing.T) {
	for _, route := range []string{"ProxyCommand", "SSHConfigProxy alias"} {
		t.Run(route, func(t *testing.T) {
			fixture := newSSMCleanupFixture(t, "normal")
			target := fixture.target()
			if route == "SSHConfigProxy alias" {
				target = fixture.configProxyTarget(t)
			}
			if err := executePreparedSSH(t.Context(), &target, "true", nil, 0, sshCommandLimit{}, "10", "1", io.Discard, io.Discard); err != nil {
				t.Fatalf("normal SSH command: %v", err)
			}
			fixture.assertAllGone(t)
		})
	}
}

func TestSSMProxyCommandCancellationReapsOnlyOwnedTransport(t *testing.T) {
	fixture := newSSMCleanupFixture(t, "cancel")
	siblingDir := t.TempDir()
	sibling := exec.Command(filepath.Join(fixture.dir, "session-manager-plugin"))
	sibling.Env = append(os.Environ(), "CRABBOX_SSM_FIXTURE="+siblingDir)
	if err := sibling.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sibling.Process.Kill(); _, _ = sibling.Process.Wait() })
	siblingSnapshot, err := inspectProcessSnapshot(sibling.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	target := fixture.target()
	go func() {
		done <- executePreparedSSH(ctx, &target, "sleep 60", nil, 0, sshCommandLimit{}, "10", "1", io.Discard, io.Discard)
	}()
	awaitSSMFixtureFile(t, filepath.Join(fixture.dir, "ssh.ready"), done)
	if len(fixture.captureLiveIdentities(t)) < 3 {
		t.Fatal("owned transport tree was not live before cancellation")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation cause=%v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled SSH command did not return")
	}
	fixture.assertAllGone(t)
	current, err := inspectProcessSnapshot(sibling.Process.Pid)
	if err != nil || current.exited || current.started != siblingSnapshot.started {
		t.Fatalf("unrelated sibling process was terminated or replaced: snapshot=%+v err=%v", current, err)
	}
}

type blockingSSMOutputWriter struct {
	entered     chan struct{}
	release     chan struct{}
	returned    chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once
}

func newBlockingSSMOutputWriter() *blockingSSMOutputWriter {
	return &blockingSSMOutputWriter{
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		returned: make(chan struct{}),
	}
}

func (w *blockingSSMOutputWriter) Write([]byte) (int, error) {
	w.enterOnce.Do(func() { close(w.entered) })
	<-w.release
	close(w.returned)
	return 0, errors.New("blocked writer released")
}

func (w *blockingSSMOutputWriter) unblock() {
	w.releaseOnce.Do(func() { close(w.release) })
}

func TestSSMProxyCommandCancellationDoesNotWaitForBlockedWriter(t *testing.T) {
	fixture := newSSMCleanupFixture(t, "blocked-output")
	writer := newBlockingSSMOutputWriter()
	t.Cleanup(writer.unblock)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	target := fixture.target()
	go func() {
		done <- executePreparedSSH(ctx, &target, "sleep 60", nil, 0, sshCommandLimit{}, "10", "1", writer, io.Discard)
	}()
	select {
	case <-writer.entered:
	case err := <-done:
		t.Fatalf("transport returned before output writer blocked: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("transport did not write fixture output")
	}
	if len(fixture.captureLiveIdentities(t)) < 3 {
		t.Fatal("owned transport tree was not live before cancellation")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation cause=%v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled SSH command waited for blocked output writer")
	}
	fixture.assertAllGone(t)
	select {
	case <-writer.returned:
		t.Fatal("blocked writer returned before the fixture released it")
	default:
	}
	writer.unblock()
	select {
	case <-writer.returned:
	case <-time.After(5 * time.Second):
		t.Fatal("output copy did not finish after blocked writer was released")
	}
}

func TestSSMProxyTunnelInterruptionReapsTransportAndReleasesPort(t *testing.T) {
	for _, mode := range []string{"cancel-during-startup", "cancel-after-ready"} {
		t.Run(mode, func(t *testing.T) {
			fixtureMode := "cancel"
			if mode == "cancel-after-ready" {
				fixtureMode = "tunnel"
			}
			fixture := newSSMCleanupFixture(t, fixtureMode)
			reservation, err := reserveSSHLocalForwardPort(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.port
			reservation.release()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			var output bytes.Buffer
			go func() { done <- runSSHLocalForward(ctx, fixture.target(), port, "8080", &output) }()
			ready := filepath.Join(fixture.dir, "ssh.ready")
			if mode == "cancel-after-ready" {
				ready = filepath.Join(fixture.dir, "tunnel.ready")
			}
			awaitSSMFixtureFile(t, ready, done)
			fixture.captureLiveIdentities(t)
			cancel()
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("interrupted tunnel: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("interrupted tunnel did not return")
			}
			fixture.assertAllGone(t)
			reused, err := reserveSSHLocalForwardPort(t.Context(), port)
			if err != nil {
				t.Fatalf("tunnel did not release owned local port %s: %v", port, err)
			}
			reused.release()
		})
	}
}

type ssmReleaseOrderingBackend struct {
	t         *testing.T
	fixture   *ssmCleanupFixture
	released  bool
	releaseID string
}

func (b *ssmReleaseOrderingBackend) Spec() ProviderSpec {
	return ProviderSpec{Name: "ssm-release-ordering-test"}
}
func (b *ssmReleaseOrderingBackend) Resolve(context.Context, ResolveRequest) (LeaseTarget, error) {
	return LeaseTarget{}, errors.New("not used")
}
func (b *ssmReleaseOrderingBackend) Touch(context.Context, TouchRequest) (Server, error) {
	return Server{}, errors.New("not used")
}
func (b *ssmReleaseOrderingBackend) Acquire(context.Context, AcquireRequest) (LeaseTarget, error) {
	return LeaseTarget{}, errors.New("not used")
}
func (b *ssmReleaseOrderingBackend) List(context.Context, ListRequest) ([]LeaseView, error) {
	return nil, errors.New("not used")
}
func (b *ssmReleaseOrderingBackend) ReleaseLease(_ context.Context, req ReleaseLeaseRequest) error {
	b.releaseID = req.Lease.LeaseID
	for _, pid := range b.fixture.pids(b.t) {
		snapshot, err := inspectProcessSnapshot(pid)
		if err == nil && !snapshot.exited {
			if started := b.fixture.startedAt[pid]; started == "" || started == snapshot.started {
				return fmt.Errorf("provider delete reached while owned SSM transport pid %d was active", pid)
			}
		}
	}
	b.released = true
	return nil
}
func (*ssmReleaseOrderingBackend) ReleaseLeaseConnectionCleanupSafe() bool { return false }

func TestWorkerReleaseWaitsForSSMTransportCleanupBeforeProviderDelete(t *testing.T) {
	fixture := newSSMCleanupFixture(t, "release")
	target := fixture.target()
	done := make(chan error, 1)
	go func() {
		done <- executePreparedSSH(t.Context(), &target, "true", nil, 0, sshCommandLimit{}, "10", "1", io.Discard, io.Discard)
	}()
	awaitSSMFixtureFile(t, filepath.Join(fixture.dir, "ssh.ready"), done)
	if live := fixture.captureLiveIdentities(t); len(live) < 3 {
		t.Fatalf("owned transport tree was not live before normal exit: pids=%v", live)
	}
	if err := os.WriteFile(filepath.Join(fixture.dir, "allow-exit"), []byte("exit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("normal SSH command did not return")
	}

	statePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(statePath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", statePath)
	backend := &ssmReleaseOrderingBackend{t: t, fixture: fixture}
	lease := LeaseTarget{LeaseID: "cbx_0123456789ab", Server: Server{Provider: backend.Spec().Name}}
	var stderr bytes.Buffer
	outcome, err := (App{Stdout: io.Discard, Stderr: &stderr}).releaseBackendLeaseWithOutcomeBestEffort(t.Context(), backend, Config{}, lease)
	if err != nil {
		t.Fatalf("release after best-effort local cleanup warning: %v\nstderr=%s", err, stderr.String())
	}
	if !backend.released || backend.releaseID != lease.LeaseID || !outcome.Terminal {
		t.Fatalf("release=%t id=%q outcome=%+v", backend.released, backend.releaseID, outcome)
	}
	if !strings.Contains(stderr.String(), "egress host daemon cleanup failed") {
		t.Fatalf("test did not exercise optional local cleanup failure: %s", stderr.String())
	}
	fixture.assertAllGone(t)
}
