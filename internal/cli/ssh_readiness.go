package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

type sshReadinessProbeStopped struct {
	probe string
	cause error
}

func (e *sshReadinessProbeStopped) Error() string { return e.cause.Error() }
func (e *sshReadinessProbeStopped) Unwrap() error { return e.cause }

// The stage names the local invocation, not evidence that remote code started.
func sshReadinessProbeContextError(ctx context.Context, probe string) *sshReadinessProbeStopped {
	cause := context.Cause(ctx)
	if cause == nil {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 0 {
			return nil
		}
		cause = context.DeadlineExceeded
	}
	return &sshReadinessProbeStopped{probe: probe, cause: cause}
}

var errSSHHostKeyVerification = errors.New("SSH host-key verification failed; verify the lease identity and its SSH host trust before reconnecting")

const sshHostKeyVerificationDiagnostic = "Host key verification failed."

type sshReadinessFailureClass string

const (
	sshReadinessFailureUnknown          sshReadinessFailureClass = "unknown"
	sshReadinessFailurePlugin           sshReadinessFailureClass = "plugin"
	sshReadinessFailureDataChannel      sshReadinessFailureClass = "data_channel"
	sshReadinessFailureIdentification   sshReadinessFailureClass = "ssh_identification"
	sshReadinessFailureAuthentication   sshReadinessFailureClass = "ssh_authentication"
	sshReadinessFailureHostKey          sshReadinessFailureClass = "host_key_verification"
	sshReadinessFailureTimeout          sshReadinessFailureClass = "timeout"
	sshReadinessFailureLifecycle        sshReadinessFailureClass = "lifecycle"
	sshReadinessFailureLifecycleCleanup sshReadinessFailureClass = "lifecycle_cleanup"
	sshReadinessFailureUnknownOutcome   sshReadinessFailureClass = "unknown_session_outcome"
	sshReadinessFailurePermissionDenied sshReadinessFailureClass = "api_permission_denied"
)

type sshReadinessDiagnosticMatcher struct {
	pattern  string
	prefixes []int
	matched  int
	seen     bool
}

func newSSHReadinessDiagnosticMatcher(pattern string) sshReadinessDiagnosticMatcher {
	prefixes := make([]int, len(pattern))
	for index, matched := 1, 0; index < len(pattern); index++ {
		for matched > 0 && pattern[index] != pattern[matched] {
			matched = prefixes[matched-1]
		}
		if pattern[index] == pattern[matched] {
			matched++
		}
		prefixes[index] = matched
	}
	return sshReadinessDiagnosticMatcher{pattern: pattern, prefixes: prefixes}
}

func (m *sshReadinessDiagnosticMatcher) writeByte(value byte) {
	if m.seen {
		return
	}
	for m.matched > 0 && value != m.pattern[m.matched] {
		m.matched = m.prefixes[m.matched-1]
	}
	if value == m.pattern[m.matched] {
		m.matched++
	}
	if m.matched == len(m.pattern) {
		m.seen = true
	}
}

// Retain only matching state, never stderr bytes. Matching survives arbitrary
// write boundaries and output volume without weakening bounded-buffer semantics.
type sshReadinessDiagnostic struct {
	mu       sync.Mutex
	matchers []sshReadinessDiagnosticMatcher
}

func (d *sshReadinessDiagnostic) initialize() {
	if d.matchers != nil {
		return
	}
	for _, pattern := range []string{
		sshHostKeyVerificationDiagnostic,
		"Permission denied (publickey",
		"Connection timed out during banner exchange",
		"kex_exchange_identification:",
		"failed to open data channel",
		"Session Manager plugin",
		"context deadline exceeded",
	} {
		d.matchers = append(d.matchers, newSSHReadinessDiagnosticMatcher(pattern))
	}
}

func (d *sshReadinessDiagnostic) Write(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.initialize()
	for _, value := range data {
		for index := range d.matchers {
			d.matchers[index].writeByte(value)
		}
	}
	return len(data), nil
}

func (d *sshReadinessDiagnostic) hostKeyRejected() bool {
	return d.failureClass() == sshReadinessFailureHostKey
}

func (d *sshReadinessDiagnostic) failureClass() sshReadinessFailureClass {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.initialize()
	classes := []sshReadinessFailureClass{
		sshReadinessFailureHostKey,
		sshReadinessFailureAuthentication,
		sshReadinessFailureIdentification,
		sshReadinessFailureIdentification,
		sshReadinessFailureDataChannel,
		sshReadinessFailurePlugin,
		sshReadinessFailureTimeout,
	}
	for index, matcher := range d.matchers {
		if matcher.seen {
			return classes[index]
		}
	}
	return ""
}

type sshReadinessClassifiedError struct {
	class    sshReadinessFailureClass
	observed sshReadinessFailureClass
	code     string
	cause    error
	fatal    bool
}

func (e *sshReadinessClassifiedError) Error() string {
	message := "SSH readiness failed class=" + string(e.class)
	if e.code != "" {
		message += " code=" + e.code
	}
	if e.observed != "" && e.observed != e.class {
		message += " observed=" + string(e.observed)
	}
	return message
}

func (e *sshReadinessClassifiedError) Unwrap() error { return e.cause }

func runSSHReadinessProbe(ctx context.Context, target SSHTarget, remote, connectTimeout, attempts string) error {
	var diagnostic sshReadinessDiagnostic
	var stderr io.Writer = &diagnostic
	if usesServeRelay(target) && os.Getenv("CRABBOX_SERVE_RELAY_DEBUG") == "1" {
		stderr = io.MultiWriter(stderr, &serveRelayDiagnosticForwarder{out: os.Stderr})
	}
	err := executeSSH(ctx, &target, remote, nil, 0, 0, connectTimeout, attempts, io.Discard, stderr)
	if err == nil {
		recordCreationObservation(ctx, "ssh_authenticated")
	}
	return sshReadinessProbeError(ctx, err, diagnostic.failureClass(), usesSSHProxyTransport(target))
}

func canWaitForLinuxReadiness(target SSHTarget) bool {
	return target.TargetOS == targetLinux && !usesSSHProxyTransport(target) && target.SSHConfigFile == ""
}

func linuxReadinessWaitCommand(target SSHTarget, timeout time.Duration) string {
	// A separate shell preserves custom predicates' exit and errexit behavior;
	// a subshell used as an && condition would suppress their set -e failures.
	loop := "while :; do\nsh -c " + shellQuote(sshReadyCommand(target)) + " && exit 0\nsleep 0.25 || exit 1\ndone"
	return "timeout " + strconv.FormatFloat(timeout.Seconds(), 'f', -1, 64) + "s sh -c " + shellQuote(loop)
}

func waitForLinuxReadiness(ctx context.Context, target SSHTarget, profile sshReadinessProfile, timeout time.Duration, progress func()) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Do not leave a new persistent master holding probe pipes on cancellation.
	// An existing workspace-owned master retains its explicit lifetime owner.
	target.NoControlMaster = true
	// The remote timeout also bounds the loop if the client disappears. Hosts
	// without timeout simply fail this optimization and retry the usual probe.
	done := make(chan error, 1)
	go func() {
		done <- runSSHReadinessProbe(waitCtx, target, linuxReadinessWaitCommand(target, timeout), profile.connectTimeout, profile.connectionAttempts)
	}()
	progress()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if waitCtx.Err() != nil {
				return context.Cause(waitCtx)
			}
			return err
		case <-ticker.C:
			progress()
		}
	}
}

func runWSLReadinessTransport(ctx context.Context, target SSHTarget, command, connectTimeout, attempts string) error {
	transport := sshTransportPreparation{command: command}
	var diagnostic sshReadinessDiagnostic
	_, err := transport.runOnce(ctx, target, connectTimeout, attempts, io.Discard, &diagnostic, false)
	if err == nil {
		err = context.Cause(ctx)
	}
	return sshReadinessProbeError(ctx, err, diagnostic.failureClass(), usesSSHProxyTransport(target))
}

func sshReadinessProbeError(ctx context.Context, err error, class sshReadinessFailureClass, proxy bool) error {
	if err == nil {
		return nil
	}
	var statusErr *proxyCommandStatusError
	if errors.As(err, &statusErr) {
		if statusErr.readinessFatal() {
			return &sshReadinessClassifiedError{
				class: sshReadinessClassForProxyFailure(statusErr.class), observed: class,
				code: statusErr.code, cause: err, fatal: true,
			}
		}
		if class == "" {
			class = sshReadinessClassForProxyFailure(statusErr.class)
		}
		return &sshReadinessClassifiedError{class: class, cause: err}
	}
	// A host-key rejection cannot recover while waiting for guest bootstrap.
	// Retain the exit cause, but never expose captured remote stderr or key data.
	if ctx.Err() == nil && exitCode(err) == 255 && class == sshReadinessFailureHostKey {
		return errors.Join(errSSHHostKeyVerification, err)
	}
	var setupErr *workspaceOwnerSetupError
	if errors.As(err, &setupErr) {
		return err
	}
	if proxy {
		if class == "" {
			class = sshReadinessFailureUnknown
		}
		return &sshReadinessClassifiedError{class: class, cause: err}
	}
	return err
}

func sshReadinessClassForProxyFailure(class proxyCommandFailureClass) sshReadinessFailureClass {
	switch class {
	case proxyCommandFailureLifecycleCleanup:
		return sshReadinessFailureLifecycleCleanup
	case proxyCommandFailureUnknownOutcome:
		return sshReadinessFailureUnknownOutcome
	case proxyCommandFailurePermissionDenied:
		return sshReadinessFailurePermissionDenied
	default:
		return sshReadinessFailureLifecycle
	}
}

func sshReadinessFailure(err error) *sshReadinessClassifiedError {
	var classified *sshReadinessClassifiedError
	if errors.As(err, &classified) {
		return classified
	}
	return nil
}

func sshReadinessError(err error, phase string) error {
	if errors.Is(err, errSSHHostKeyVerification) {
		return fmt.Errorf("%s: %w", phase, err)
	}
	if classified := sshReadinessFailure(err); classified != nil && classified.fatal {
		return fmt.Errorf("%s: %w", phase, classified)
	}
	return workspaceOwnerReadinessError(err, phase)
}
