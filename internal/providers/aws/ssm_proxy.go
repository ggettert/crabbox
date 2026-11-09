package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	awsdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go"
	core "github.com/openclaw/crabbox/internal/cli"
)

const (
	awsSSMProxyDocument      = "AWS-StartSSHSession"
	awsSSMProxyResponseEnv   = "AWS_SSM_START_SESSION_RESPONSE"
	awsSSMProxyDiagnosticMax = 64 * 1024
	awsSSMProxyHangupSignal  = syscall.Signal(1)
)

var (
	awsSSMProxyTargetPattern       = regexp.MustCompile(`^i-[0-9a-f]{8,32}$`)
	awsSSMProxyRegionPattern       = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$`)
	awsSSMProxyStartLimit          = 30 * time.Second
	awsSSMProxyStartCancelLimit    = 2 * time.Second
	awsSSMProxyPluginShutdownLimit = 2 * time.Second
	awsSSMProxyCleanupLimit        = 3 * time.Second
	newSSMProxyClient              = loadSSMProxyClient
)

type ssmProxyAPI interface {
	StartSession(context.Context, *ssm.StartSessionInput, ...func(*ssm.Options)) (*ssm.StartSessionOutput, error)
	TerminateSession(context.Context, *ssm.TerminateSessionInput, ...func(*ssm.Options)) (*ssm.TerminateSessionOutput, error)
}

type ssmProxyOptions struct {
	target string
	region string
	port   string
	plugin string
}

type ssmProxyLifecycleReporter struct {
	dir string
}

func RunSSMProxyCLI(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, awsSSMProxyHangupSignal)
	defer stop()
	opts, err := parseSSMProxyOptions(args)
	if err != nil {
		return core.Exit(2, "%v", err)
	}
	reporter, err := newSSMProxyLifecycleReporter()
	if err != nil {
		return err
	}
	return runSSMProxy(ctx, opts, reporter, stdin, stdout, stderr)
}

func parseSSMProxyOptions(args []string) (ssmProxyOptions, error) {
	var opts ssmProxyOptions
	flags := flag.NewFlagSet("__aws-ssm-proxy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.target, "target", "", "")
	flags.StringVar(&opts.region, "region", "", "")
	flags.StringVar(&opts.port, "port", "", "")
	flags.StringVar(&opts.plugin, "plugin", "", "")
	if err := flags.Parse(args); err != nil {
		return ssmProxyOptions{}, fmt.Errorf("invalid AWS SSM proxy arguments")
	}
	if flags.NArg() != 0 {
		return ssmProxyOptions{}, fmt.Errorf("AWS SSM proxy does not accept positional arguments")
	}
	if !awsSSMProxyTargetPattern.MatchString(opts.target) {
		return ssmProxyOptions{}, fmt.Errorf("AWS SSM proxy target must be an EC2 instance ID")
	}
	if !awsSSMProxyRegionPattern.MatchString(opts.region) {
		return ssmProxyOptions{}, fmt.Errorf("AWS SSM proxy region is invalid")
	}
	port, err := strconv.Atoi(opts.port)
	if err != nil || port < 1 || port > 65535 {
		return ssmProxyOptions{}, fmt.Errorf("AWS SSM proxy port must be in 1..65535")
	}
	if !filepath.IsAbs(opts.plugin) || filepath.Base(opts.plugin) != "session-manager-plugin" {
		return ssmProxyOptions{}, fmt.Errorf("AWS SSM proxy plugin must be an absolute session-manager-plugin path")
	}
	info, err := os.Stat(opts.plugin)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return ssmProxyOptions{}, fmt.Errorf("AWS SSM proxy plugin path is not executable")
	}
	return opts, nil
}

func loadSSMProxyClient(ctx context.Context, region string) (ssmProxyAPI, string, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, "", safeSSMProxyError("load AWS SDK configuration", err)
	}
	endpoint, err := ssm.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, ssm.EndpointParameters{Region: awsdk.String(region)})
	if err != nil {
		return nil, "", safeSSMProxyError("resolve SSM endpoint", err)
	}
	return ssm.NewFromConfig(cfg), endpoint.URI.String(), nil
}

func runSSMProxy(ctx context.Context, opts ssmProxyOptions, reporter *ssmProxyLifecycleReporter, stdin io.Reader, stdout, stderr io.Writer) (retErr error) {
	var lifecycleErr error
	defer func() {
		reportErr := reporter.finish(lifecycleErr)
		retErr = errors.Join(retErr, reportErr)
	}()
	client, endpoint, err := newSSMProxyClient(ctx, opts.region)
	if err != nil {
		if context.Cause(ctx) == nil {
			lifecycleErr = err
		}
		return err
	}
	input := &ssm.StartSessionInput{
		Target:       awsdk.String(opts.target),
		DocumentName: awsdk.String(awsSSMProxyDocument),
		Parameters:   map[string][]string{"portNumber": {opts.port}},
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	response, err := startSSMProxySession(ctx, client, input)
	sessionID := ""
	if response != nil {
		sessionID = awsdk.ToString(response.SessionId)
	}
	if err != nil {
		startErr := safeSSMProxyError("start SSM session", err)
		if sessionID == "" {
			outcome := errors.New("SSM session start outcome is unknown because no session ID was returned")
			if isDefiniteSSMStartRejection(err) {
				outcome = errors.New("SSM session start was rejected before a session was created")
			}
			lifecycleErr = errors.Join(startErr, outcome)
			return lifecycleErr
		}
		owner := ssmProxySessionOwner{client: client, sessionID: sessionID}
		lifecycleErr = errors.Join(startErr, owner.close(ctx))
		return lifecycleErr
	}
	if response == nil || sessionID == "" {
		lifecycleErr = errors.Join(
			errors.New("start SSM session returned an incomplete response"),
			errors.New("SSM session start outcome is unknown because no session ID was returned"),
		)
		return lifecycleErr
	}
	owner := ssmProxySessionOwner{client: client, sessionID: sessionID}
	if err := context.Cause(ctx); err != nil {
		lifecycleErr = owner.close(ctx)
		return errors.Join(err, lifecycleErr)
	}
	if awsdk.ToString(response.TokenValue) == "" || awsdk.ToString(response.StreamUrl) == "" {
		lifecycleErr = errors.Join(errors.New("start SSM session returned an incomplete response"), owner.close(ctx))
		return lifecycleErr
	}
	pluginDone := make(chan error, 1)
	go func() {
		pluginDone <- runSSMPlugin(ctx, opts, endpoint, input, response, stdin, stdout, stderr)
	}()
	select {
	case pluginErr := <-pluginDone:
		cleanupErr := owner.close(ctx)
		if context.Cause(ctx) != nil {
			retErr = context.Cause(ctx)
			pluginErr = nil
		}
		lifecycleErr = errors.Join(pluginErr, cleanupErr)
		return errors.Join(retErr, lifecycleErr)
	case <-ctx.Done():
	}
	cleanupDone := make(chan error, 1)
	go func() { cleanupDone <- owner.close(ctx) }()
	var pluginErr error
	pluginTimer := time.NewTimer(awsSSMProxyPluginShutdownLimit)
	select {
	case <-pluginDone:
	case <-pluginTimer.C:
		pluginErr = errors.New("Session Manager plugin did not stop before the shutdown deadline")
	}
	if !pluginTimer.Stop() {
		select {
		case <-pluginTimer.C:
		default:
		}
	}
	cleanupErr := <-cleanupDone
	retErr = context.Cause(ctx)
	lifecycleErr = errors.Join(pluginErr, cleanupErr)
	return errors.Join(retErr, lifecycleErr)
}

type ssmProxyStartResult struct {
	response *ssm.StartSessionOutput
	err      error
}

func startSSMProxySession(parent context.Context, client ssmProxyAPI, input *ssm.StartSessionInput) (*ssm.StartSessionOutput, error) {
	ctx, cancel := context.WithTimeout(parent, awsSSMProxyStartLimit)
	defer cancel()
	done := make(chan ssmProxyStartResult, 1)
	go func() {
		response, err := client.StartSession(ctx, input, func(options *ssm.Options) {
			options.RetryMaxAttempts = 1
		})
		done <- ssmProxyStartResult{response: response, err: err}
	}()
	select {
	case result := <-done:
		return result.response, result.err
	case <-ctx.Done():
	}
	timer := time.NewTimer(awsSSMProxyStartCancelLimit)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.response, result.err
	case <-timer.C:
		return nil, ctx.Err()
	}
}

type ssmProxySessionOwner struct {
	client    ssmProxyAPI
	sessionID string
	once      sync.Once
	err       error
}

func (o *ssmProxySessionOwner) close(parent context.Context) error {
	o.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), awsSSMProxyCleanupLimit)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := o.client.TerminateSession(ctx, &ssm.TerminateSessionInput{SessionId: awsdk.String(o.sessionID)}, func(options *ssm.Options) {
				options.RetryMaxAttempts = 1
			})
			done <- err
		}()
		var err error
		select {
		case err = <-done:
		case <-ctx.Done():
			err = ctx.Err()
		}
		if isClosedSSMSessionError(err) {
			return
		}
		if err != nil {
			o.err = safeSSMProxyError("terminate owned SSM session", err)
		}
	})
	return o.err
}

func isClosedSSMSessionError(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AlreadyTerminated", "DoesNotExistException":
		return true
	default:
		return false
	}
}

func runSSMPlugin(ctx context.Context, opts ssmProxyOptions, endpoint string, input *ssm.StartSessionInput, response *ssm.StartSessionOutput, stdin io.Reader, stdout, stderr io.Writer) error {
	responseJSON, err := json.Marshal(struct {
		SessionID  string `json:"SessionId"`
		TokenValue string `json:"TokenValue"`
		StreamURL  string `json:"StreamUrl"`
	}{awsdk.ToString(response.SessionId), awsdk.ToString(response.TokenValue), awsdk.ToString(response.StreamUrl)})
	if err != nil {
		return errors.New("encode SSM plugin response")
	}
	requestJSON, err := json.Marshal(struct {
		Target       string              `json:"Target"`
		DocumentName string              `json:"DocumentName"`
		Parameters   map[string][]string `json:"Parameters"`
	}{awsdk.ToString(input.Target), awsdk.ToString(input.DocumentName), input.Parameters})
	if err != nil {
		return errors.New("encode SSM plugin request")
	}
	cmd := exec.CommandContext(ctx, opts.plugin,
		awsSSMProxyResponseEnv, opts.region, "StartSession", "", string(requestJSON), endpoint,
	)
	cmd.Env = environmentWithOverride(os.Environ(), awsSSMProxyResponseEnv, string(responseJSON))
	cmd.Stdin = stdin
	diagnostic := &boundedSSMProxyDiagnostic{limit: awsSSMProxyDiagnosticMax}
	cmd.Stderr = diagnostic
	pluginOutput, pluginWriter, err := os.Pipe()
	if err != nil {
		return errors.New("prepare Session Manager plugin output")
	}
	cmd.Stdout = pluginWriter
	if err := cmd.Start(); err != nil {
		return errors.Join(safeSSMProxyError("Session Manager plugin", err), pluginOutput.Close(), pluginWriter.Close())
	}
	_ = pluginWriter.Close()
	copyDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(stdout, pluginOutput)
		copyDone <- errors.Join(copyErr, pluginOutput.Close())
	}()
	err = cmd.Wait()
	var copyErr error
	select {
	case copyErr = <-copyDone:
	case <-ctx.Done():
		// API cleanup must not wait for an arbitrary caller-owned output writer.
	}
	redacted := redactSSMProxyDiagnostic(diagnostic.String(), response)
	if redacted != "" {
		_, _ = fmt.Fprint(stderr, redacted)
		if !strings.HasSuffix(redacted, "\n") {
			_, _ = fmt.Fprintln(stderr)
		}
	}
	if err != nil || copyErr != nil {
		var outputErr error
		if copyErr != nil {
			outputErr = errors.New("stream Session Manager plugin output failed")
		}
		return errors.Join(safeSSMProxyError("Session Manager plugin", err), outputErr)
	}
	return nil
}

func environmentWithOverride(env []string, name, value string) []string {
	prefix := name + "="
	result := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}

type boundedSSMProxyDiagnostic struct {
	buffer bytes.Buffer
	limit  int
}

func (w *boundedSSMProxyDiagnostic) Write(data []byte) (int, error) {
	remaining := w.limit - w.buffer.Len()
	if remaining > 0 {
		_, _ = w.buffer.Write(data[:min(remaining, len(data))])
	}
	return len(data), nil
}

func (w *boundedSSMProxyDiagnostic) String() string { return w.buffer.String() }

func redactSSMProxyDiagnostic(value string, response *ssm.StartSessionOutput) string {
	return core.RedactDiagnosticSecrets(value,
		awsdk.ToString(response.TokenValue),
		awsdk.ToString(response.StreamUrl),
	)
}

func isDefiniteSSMStartRejection(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "TargetNotConnected", "ThrottlingException", "ThrottledException", "TooManyRequestsException", "RequestLimitExceeded",
		"AccessDeniedException", "UnauthorizedException", "UnrecognizedClientException", "InvalidClientTokenId",
		"ValidationException", "InvalidParameters", "InvalidInstanceId", "UnsupportedOperationException":
		return true
	default:
		return false
	}
}

func safeSSMProxyError(action string, err error) error {
	if err == nil {
		return nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("%s: AWS API error %s", action, apiErr.ErrorCode())
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %w", action, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", action, context.DeadlineExceeded)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Errorf("%s exited with status %d", action, exitErr.ExitCode())
	}
	return fmt.Errorf("%s failed", action)
}

func newSSMProxyLifecycleReporter() (*ssmProxyLifecycleReporter, error) {
	dir := os.Getenv(core.ProxyCommandStatusEnvironment)
	if !filepath.IsAbs(dir) {
		return nil, errors.New("AWS SSM proxy lifecycle directory is unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("AWS SSM proxy lifecycle directory is unsafe")
	}
	reporter := &ssmProxyLifecycleReporter{dir: dir}
	if err := reporter.writeExclusive("started", "started\n"); err != nil {
		return nil, fmt.Errorf("initialize AWS SSM proxy lifecycle status: %w", err)
	}
	return reporter, nil
}

func (r *ssmProxyLifecycleReporter) finish(err error) error {
	result := "ok\n"
	if err != nil {
		result = "error: " + err.Error() + "\n"
	}
	file, writeErr := os.CreateTemp(r.dir, ".result-*")
	if writeErr != nil {
		return writeErr
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if chmodErr := file.Chmod(0o600); chmodErr != nil {
		return errors.Join(chmodErr, file.Close())
	}
	_, writeErr = io.WriteString(file, result)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(writeErr, closeErr)
	}
	return os.Rename(tempPath, filepath.Join(r.dir, "result"))
}

func (r *ssmProxyLifecycleReporter) writeExclusive(name, value string) error {
	file, err := os.OpenFile(filepath.Join(r.dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := io.WriteString(file, value)
	return errors.Join(writeErr, file.Close())
}
