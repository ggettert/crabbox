package aws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	awsdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go"
	core "github.com/openclaw/crabbox/internal/cli"
)

type fakeSSMProxyAPI struct {
	mu             sync.Mutex
	start          func(context.Context, *ssm.StartSessionInput) (*ssm.StartSessionOutput, error)
	terminate      func(context.Context, *ssm.TerminateSessionInput) error
	startCalls     int
	terminateCalls []string
}

type blockingSSMProxyWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingSSMProxyWriter) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(data), nil
}

func (f *fakeSSMProxyAPI) StartSession(ctx context.Context, input *ssm.StartSessionInput, _ ...func(*ssm.Options)) (*ssm.StartSessionOutput, error) {
	f.mu.Lock()
	f.startCalls++
	f.mu.Unlock()
	if f.start != nil {
		return f.start(ctx, input)
	}
	return fixtureSSMStartSessionOutput("session-owned"), nil
}

func (f *fakeSSMProxyAPI) TerminateSession(ctx context.Context, input *ssm.TerminateSessionInput, _ ...func(*ssm.Options)) (*ssm.TerminateSessionOutput, error) {
	sessionID := awsdk.ToString(input.SessionId)
	f.mu.Lock()
	f.terminateCalls = append(f.terminateCalls, sessionID)
	f.mu.Unlock()
	if f.terminate != nil {
		if err := f.terminate(ctx, input); err != nil {
			return nil, err
		}
	}
	return &ssm.TerminateSessionOutput{SessionId: input.SessionId}, nil
}

func fixtureSSMStartSessionOutput(sessionID string) *ssm.StartSessionOutput {
	return &ssm.StartSessionOutput{
		SessionId:  awsdk.String(sessionID),
		TokenValue: awsdk.String("fixture-secret-token"),
		StreamUrl:  awsdk.String("wss://fixture.invalid/secret-stream"),
	}
}

func installSSMProxyClient(t *testing.T, client ssmProxyAPI) {
	t.Helper()
	previous := newSSMProxyClient
	newSSMProxyClient = func(context.Context, string) (ssmProxyAPI, string, error) {
		return client, "https://ssm.us-test-1.amazonaws.com", nil
	}
	t.Cleanup(func() { newSSMProxyClient = previous })
}

func testSSMProxyReporter(t *testing.T) *ssmProxyLifecycleReporter {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	reporter := &ssmProxyLifecycleReporter{dir: dir}
	if err := reporter.writeExclusive("started", "started\n"); err != nil {
		t.Fatal(err)
	}
	return reporter
}

func testSSMProxyPlugin(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session-manager-plugin")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSSMProxyRejectsInvalidArgumentsBeforeSDKOrPlugin(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "exit 99")
	previous := newSSMProxyClient
	called := false
	newSSMProxyClient = func(context.Context, string) (ssmProxyAPI, string, error) {
		called = true
		return nil, "", errors.New("unexpected")
	}
	t.Cleanup(func() { newSSMProxyClient = previous })
	tests := [][]string{
		{"--target", "not-an-instance", "--region", "us-test-1", "--port", "22", "--plugin", plugin},
		{"--target", "i-0123456789abcdef0", "--region", "bad", "--port", "22", "--plugin", plugin},
		{"--target", "i-0123456789abcdef0", "--region", "us-test-1", "--port", "0", "--plugin", plugin},
		{"--target", "i-0123456789abcdef0", "--region", "us-test-1", "--port", "22", "--plugin", plugin, "extra"},
		{"--target", "i-0123456789abcdef0", "--region", "us-test-1", "--port", "22", "--plugin", filepath.Join(filepath.Dir(plugin), "other-plugin")},
	}
	for _, args := range tests {
		if err := RunSSMProxyCLI(t.Context(), args, nil, io.Discard, io.Discard); err == nil {
			t.Fatalf("args=%q unexpectedly accepted", args)
		}
	}
	if called {
		t.Fatal("invalid arguments reached the AWS SDK")
	}
}

func TestSSMProxyNormalExitOwnsExactSessionAndPluginContract(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	responsePath := filepath.Join(dir, "response")
	plugin := testSSMProxyPlugin(t, "printf '%s\\n' \"$@\" > '"+argsPath+"'\nprintf '%s' \"$AWS_SSM_START_SESSION_RESPONSE\" > '"+responsePath+"'\nprintf 'plugin-wire'\nprintf '%s %s\\n' fixture-secret-token wss://fixture.invalid/secret-stream >&2")
	client := &fakeSSMProxyAPI{start: func(_ context.Context, input *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
		if awsdk.ToString(input.Target) != "i-0123456789abcdef0" || awsdk.ToString(input.DocumentName) != awsSSMProxyDocument || len(input.Parameters["portNumber"]) != 1 || input.Parameters["portNumber"][0] != "2207" {
			t.Fatalf("start input=%#v", input)
		}
		return fixtureSSMStartSessionOutput("session-owned"), nil
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	var stdout, stderr bytes.Buffer
	err := runSSMProxy(t.Context(), ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "2207", plugin: plugin}, reporter, strings.NewReader("ssh-wire"), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "plugin-wire" {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if strings.Contains(stderr.String(), "fixture-secret-token") || strings.Contains(stderr.String(), "secret-stream") {
		t.Fatalf("stderr leaked response secrets: %q", stderr.String())
	}
	if len(client.terminateCalls) != 1 || client.terminateCalls[0] != "session-owned" {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AWS_SSM_START_SESSION_RESPONSE", "us-test-1", "StartSession", `"Target":"i-0123456789abcdef0"`, `"DocumentName":"AWS-StartSSHSession"`, `"portNumber":["2207"]`, "https://ssm.us-test-1.amazonaws.com"} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("plugin args missing %q: %s", want, args)
		}
	}
	response, err := os.ReadFile(responsePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(response, []byte("fixture-secret-token")) || bytes.Contains(args, []byte("fixture-secret-token")) {
		t.Fatalf("response env/argv contract invalid: response=%q args=%q", response, args)
	}
	result, err := os.ReadFile(filepath.Join(reporter.dir, "result"))
	if err != nil || string(result) != "ok\n" {
		t.Fatalf("lifecycle result=%q err=%v", result, err)
	}
}

func TestSSMProxyStartFailureDoesNotTerminateOrLaunchPlugin(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "plugin-ran")
	plugin := testSSMProxyPlugin(t, "touch '"+marker+"'")
	client := &fakeSSMProxyAPI{start: func(context.Context, *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
		return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "fixture-secret-token"}
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	err := runSSMProxy(t.Context(), ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") || strings.Contains(err.Error(), "fixture-secret-token") {
		t.Fatalf("error=%v", err)
	}
	if len(client.terminateCalls) != 0 {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("plugin ran after start failure: %v", err)
	}
}

func TestSSMProxyStartFailureOutcomeClassification(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "exit 99")
	for _, test := range []struct {
		name        string
		err         error
		want        string
		wantUnknown bool
	}{
		{name: "target not connected", err: &smithy.GenericAPIError{Code: "TargetNotConnected", Message: "private target detail", Fault: smithy.FaultClient}, want: "TargetNotConnected"},
		{name: "throttled", err: &smithy.GenericAPIError{Code: "ThrottlingException", Message: "private throttle detail", Fault: smithy.FaultClient}, want: "ThrottlingException"},
		{name: "access denied despite cancellation wrapper", err: errors.Join(context.Canceled, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "private auth detail", Fault: smithy.FaultClient}), want: "AccessDeniedException"},
		{name: "validation", err: &smithy.GenericAPIError{Code: "ValidationException", Message: "private validation detail", Fault: smithy.FaultClient}, want: "ValidationException"},
		{name: "server fault", err: &smithy.GenericAPIError{Code: "InternalServerError", Message: "private server detail", Fault: smithy.FaultServer}, want: "InternalServerError", wantUnknown: true},
		{name: "network timeout", err: context.DeadlineExceeded, want: "context deadline exceeded", wantUnknown: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeSSMProxyAPI{start: func(context.Context, *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
				return nil, test.err
			}}
			installSSMProxyClient(t, client)
			reporter := testSSMProxyReporter(t)
			err := runSSMProxy(t.Context(), ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v", err)
			}
			if got := strings.Contains(err.Error(), "SSM session start outcome is unknown"); got != test.wantUnknown {
				t.Fatalf("unknown=%t want=%t error=%v", got, test.wantUnknown, err)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatalf("error leaked service message: %v", err)
			}
			if client.startCalls != 1 || len(client.terminateCalls) != 0 {
				t.Fatalf("start=%d terminate=%q", client.startCalls, client.terminateCalls)
			}
		})
	}
}

func TestSSMProxyCancellationWithResponseAndErrorTerminatesCapturedSessionID(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "exit 99")
	startIssued := make(chan struct{})
	client := &fakeSSMProxyAPI{start: func(ctx context.Context, _ *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
		close(startIssued)
		<-ctx.Done()
		return fixtureSSMStartSessionOutput("session-canceled-response"), ctx.Err()
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runSSMProxy(ctx, ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard)
	}()
	<-startIssued
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if len(client.terminateCalls) != 1 || client.terminateCalls[0] != "session-canceled-response" {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
}

func TestSSMProxyCancellationWaitsForDelayedOwnedResponseAndCleanup(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "exit 99")
	previousStartCancelLimit := awsSSMProxyStartCancelLimit
	previousCleanupLimit := awsSSMProxyCleanupLimit
	awsSSMProxyStartCancelLimit = 250 * time.Millisecond
	awsSSMProxyCleanupLimit = 250 * time.Millisecond
	t.Cleanup(func() {
		awsSSMProxyStartCancelLimit = previousStartCancelLimit
		awsSSMProxyCleanupLimit = previousCleanupLimit
	})
	startIssued := make(chan struct{})
	releaseStart := make(chan struct{})
	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	client := &fakeSSMProxyAPI{
		start: func(ctx context.Context, _ *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
			close(startIssued)
			<-ctx.Done()
			<-releaseStart
			return fixtureSSMStartSessionOutput("session-delayed-response"), ctx.Err()
		},
		terminate: func(context.Context, *ssm.TerminateSessionInput) error {
			close(cleanupStarted)
			<-releaseCleanup
			return nil
		},
	}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runSSMProxy(ctx, ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard)
	}()
	<-startIssued
	cancel()
	close(releaseStart)
	select {
	case <-cleanupStarted:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("cleanup did not start after the canceled request returned its session ID")
	}
	select {
	case err := <-done:
		t.Fatalf("helper returned before owned-session cleanup completed: %v", err)
	default:
	}
	close(releaseCleanup)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if len(client.terminateCalls) != 1 || client.terminateCalls[0] != "session-delayed-response" {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
}

func TestSSMProxyCancellationWithoutSessionIDReportsUnknownOutcome(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "exit 99")
	startIssued := make(chan struct{})
	client := &fakeSSMProxyAPI{start: func(ctx context.Context, _ *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
		close(startIssued)
		<-ctx.Done()
		return nil, errors.New("fixture-secret-token")
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runSSMProxy(ctx, ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard)
	}()
	<-startIssued
	cancel()
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "outcome is unknown") || strings.Contains(err.Error(), "fixture-secret-token") {
		t.Fatalf("error=%v", err)
	}
	result, readErr := os.ReadFile(filepath.Join(reporter.dir, "result"))
	if readErr != nil || !bytes.Contains(result, []byte("outcome is unknown")) || bytes.Contains(result, []byte("fixture-secret-token")) {
		t.Fatalf("result=%q err=%v", result, readErr)
	}
	if len(client.terminateCalls) != 0 {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
}

func TestSSMProxyCancellationBeforeStartRequestReportsCleanCancellation(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "exit 99")
	client := &fakeSSMProxyAPI{}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runSSMProxy(ctx, ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if client.startCalls != 0 || len(client.terminateCalls) != 0 {
		t.Fatalf("start calls=%d terminate calls=%q", client.startCalls, client.terminateCalls)
	}
	result, readErr := os.ReadFile(filepath.Join(reporter.dir, "result"))
	if readErr != nil || string(result) != "ok\n" {
		t.Fatalf("result=%q err=%v", result, readErr)
	}
}

func TestSSMProxyIncompleteResponseTerminatesCapturedSessionID(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "exit 99")
	client := &fakeSSMProxyAPI{start: func(context.Context, *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
		return &ssm.StartSessionOutput{SessionId: awsdk.String("session-incomplete")}, nil
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	err := runSSMProxy(t.Context(), ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "incomplete response") {
		t.Fatalf("error=%v", err)
	}
	if len(client.terminateCalls) != 1 || client.terminateCalls[0] != "session-incomplete" {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
}

func TestSSMProxyPluginStartFailureStillTerminatesOwnedSession(t *testing.T) {
	client := &fakeSSMProxyAPI{}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	err := runSSMProxy(t.Context(), ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: filepath.Join(t.TempDir(), "missing-plugin")}, reporter, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "Session Manager plugin failed") {
		t.Fatalf("error=%v", err)
	}
	if len(client.terminateCalls) != 1 || client.terminateCalls[0] != "session-owned" {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
}

func TestSSMProxyPluginFailureJoinsCleanupFailureWithoutSecrets(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "printf '%s\\n' fixture-secret-token >&2\nexit 17")
	client := &fakeSSMProxyAPI{terminate: func(context.Context, *ssm.TerminateSessionInput) error {
		return &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "wss://fixture.invalid/secret-stream"}
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	var stderr bytes.Buffer
	err := runSSMProxy(t.Context(), ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, &stderr)
	if err == nil || !strings.Contains(err.Error(), "status 17") || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Fatalf("error=%v", err)
	}
	result, readErr := os.ReadFile(filepath.Join(reporter.dir, "result"))
	if readErr != nil || !bytes.Contains(result, []byte("status 17")) || !bytes.Contains(result, []byte("AccessDeniedException")) {
		t.Fatalf("result=%q err=%v", result, readErr)
	}
	if strings.Contains(err.Error()+stderr.String()+string(result), "fixture-secret-token") || strings.Contains(err.Error()+stderr.String()+string(result), "secret-stream") {
		t.Fatal("diagnostics leaked SSM response secrets")
	}
}

func TestSSMProxyCancellationUsesIndependentBoundedCleanupContext(t *testing.T) {
	pluginStarted := make(chan struct{})
	marker := filepath.Join(t.TempDir(), "started")
	plugin := testSSMProxyPlugin(t, "printf started > '"+marker+"'\nexec sleep 60")
	client := &fakeSSMProxyAPI{terminate: func(ctx context.Context, input *ssm.TerminateSessionInput) error {
		if ctx.Err() != nil {
			t.Fatalf("cleanup inherited cancellation: %v", ctx.Err())
		}
		if awsdk.ToString(input.SessionId) != "session-owned" {
			t.Fatalf("cleanup session=%q", awsdk.ToString(input.SessionId))
		}
		close(pluginStarted)
		return nil
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runSSMProxy(ctx, ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("plugin did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-pluginStarted:
	case <-time.After(time.Second):
		t.Fatal("cleanup was not called after cancellation")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	result, err := os.ReadFile(filepath.Join(reporter.dir, "result"))
	if err != nil || string(result) != "ok\n" {
		t.Fatalf("result=%q err=%v", result, err)
	}
}

func TestSSMProxyCancellationCleansUpWithoutWaitingForBlockedOutputWriter(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "printf wire\nexec sleep 60")
	cleaned := make(chan struct{})
	client := &fakeSSMProxyAPI{terminate: func(context.Context, *ssm.TerminateSessionInput) error {
		close(cleaned)
		return nil
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	writer := &blockingSSMProxyWriter{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(writer.release) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runSSMProxy(ctx, ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, writer, io.Discard)
	}()
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("plugin output did not reach blocking writer")
	}
	cancel()
	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("cleanup waited for blocked output writer")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestSSMProxyOwnsResponseReturnedDuringStartupCancellationRace(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "plugin-ran")
	plugin := testSSMProxyPlugin(t, "touch '"+marker+"'")
	startIssued := make(chan struct{})
	client := &fakeSSMProxyAPI{start: func(ctx context.Context, _ *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
		close(startIssued)
		<-ctx.Done()
		return fixtureSSMStartSessionOutput("session-race"), nil
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runSSMProxy(ctx, ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard)
	}()
	<-startIssued
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if len(client.terminateCalls) != 1 || client.terminateCalls[0] != "session-race" {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("plugin ran after startup cancellation: %v", err)
	}
}

func TestConcurrentSSMProxiesTerminateOnlyTheirOwnedSessions(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "exit 0")
	client := &fakeSSMProxyAPI{start: func(_ context.Context, input *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
		return fixtureSSMStartSessionOutput("session-" + awsdk.ToString(input.Target)), nil
	}}
	installSSMProxyClient(t, client)
	const count = 10
	reporters := make([]*ssmProxyLifecycleReporter, count)
	for index := range count {
		reporters[index] = testSSMProxyReporter(t)
	}
	var workers sync.WaitGroup
	errs := make(chan error, count)
	for index := range count {
		workers.Add(1)
		go func() {
			defer workers.Done()
			target := "i-0123456789abcde" + string(rune('a'+index))
			errs <- runSSMProxy(t.Context(), ssmProxyOptions{target: target, region: "us-test-1", port: "22", plugin: plugin}, reporters[index], nil, io.Discard, io.Discard)
		}()
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.terminateCalls) != count {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
	seen := map[string]bool{}
	for _, sessionID := range client.terminateCalls {
		if seen[sessionID] {
			t.Fatalf("session terminated twice: %s", sessionID)
		}
		seen[sessionID] = true
	}
}

func TestSSMProxyCleanupTimeoutIsVisibleAndDoesNotTerminateOtherSessions(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "exit 0")
	previousLimit := awsSSMProxyCleanupLimit
	awsSSMProxyCleanupLimit = 25 * time.Millisecond
	t.Cleanup(func() { awsSSMProxyCleanupLimit = previousLimit })
	client := &fakeSSMProxyAPI{terminate: func(ctx context.Context, _ *ssm.TerminateSessionInput) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	err := runSSMProxy(t.Context(), ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("error=%v", err)
	}
	if len(client.terminateCalls) != 1 || client.terminateCalls[0] != "session-owned" {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
}

func TestSSMProxyAlreadyClosedSessionIsSuccessful(t *testing.T) {
	plugin := testSSMProxyPlugin(t, "exit 0")
	client := &fakeSSMProxyAPI{terminate: func(context.Context, *ssm.TerminateSessionInput) error {
		return &smithy.GenericAPIError{Code: "DoesNotExistException", Message: "gone"}
	}}
	installSSMProxyClient(t, client)
	reporter := testSSMProxyReporter(t)
	if err := runSSMProxy(t.Context(), ssmProxyOptions{target: "i-0123456789abcdef0", region: "us-test-1", port: "22", plugin: plugin}, reporter, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestSSMProxySessionCleanupIsIdempotent(t *testing.T) {
	client := &fakeSSMProxyAPI{}
	owner := &ssmProxySessionOwner{client: client, sessionID: "session-owned"}
	if err := owner.close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := owner.close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(client.terminateCalls) != 1 || client.terminateCalls[0] != "session-owned" {
		t.Fatalf("terminate calls=%q", client.terminateCalls)
	}
}

func TestSSMProxyLifecycleReporterRequiresPrivateDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(core.ProxyCommandStatusEnvironment, dir)
	if _, err := newSSMProxyLifecycleReporter(); err == nil {
		t.Fatal("unsafe lifecycle directory accepted")
	}
}
