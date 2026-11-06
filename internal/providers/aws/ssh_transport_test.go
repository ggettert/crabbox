package aws

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	core "github.com/openclaw/crabbox/internal/cli"
	"github.com/openclaw/crabbox/internal/testutil"
)

func installAWSSSMDependencies(t *testing.T, executable string) {
	t.Helper()
	previousLookPath := awsSSMLookPath
	previousExecutable := awsSSMExecutable
	awsSSMLookPath = func(name string) (string, error) {
		if name == "session-manager-plugin" {
			return "/fixture/session-manager-plugin", nil
		}
		return "", exec.ErrNotFound
	}
	awsSSMExecutable = func() (string, error) { return executable, nil }
	t.Cleanup(func() {
		awsSSMLookPath = previousLookPath
		awsSSMExecutable = previousExecutable
	})
}

func TestAWSSSMTransportValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		cfg  core.Config
		want string
	}{
		{name: "default direct", cfg: core.Config{TargetOS: core.TargetWindows}},
		{name: "linux SSM", cfg: core.Config{TargetOS: core.TargetLinux, AWSSSHTransport: " SSM "}},
		{name: "unknown transport", cfg: core.Config{TargetOS: core.TargetLinux, AWSSSHTransport: "tunnel"}, want: "must be"},
		{name: "Windows SSM", cfg: core.Config{TargetOS: core.TargetWindows, AWSSSHTransport: core.AWSSSHTransportSSM}, want: "Linux targets only"},
		{name: "macOS SSM", cfg: core.Config{TargetOS: core.TargetMacOS, AWSSSHTransport: core.AWSSSHTransportSSM}, want: "Linux targets only"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := (Provider{}).ValidateConfig(test.cfg)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestAWSSSMProxyCommandUsesInstanceRegionAndSSHPort(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	cliDir := filepath.Join(dir, "crabbox % fixture;$(literal)")
	if err := os.MkdirAll(cliDir, 0o755); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(cliDir, "crabbox cli")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + argsFile + "\"\n"
	if err := os.WriteFile(executable, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	installAWSSSMDependencies(t, executable)
	cfg := core.Config{
		Provider: "aws", TargetOS: core.TargetLinux, AWSRegion: "us-west-2",
		AWSSSHTransport: core.AWSSSHTransportSSM, AWSProfile: "ec2-instance-profile-not-cli-profile", SSHPort: "2207",
	}
	server := awsTestServer("i-0123456789abcdef0", "cbx_abcdef123456", "private", "eu-west-1")
	server.Labels["aws_ssh_transport"] = core.AWSSSHTransportSSM
	target, err := sshTargetForAWSServer(cfg, server, "203.0.113.10", false)
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != server.CloudID || target.Port != "2207" || target.ProxyCommand == "" || !target.ProxyCommandStatus || !target.NoControlMaster {
		t.Fatalf("target=%#v", target)
	}
	if strings.Contains(target.ProxyCommand, cfg.AWSProfile) || !strings.Contains(target.ProxyCommand, "--port %p") {
		t.Fatalf("proxy=%q", target.ProxyCommand)
	}
	command := expandSSHProxyCommandForTest(target.ProxyCommand, target.Port)
	if output, err := exec.Command("sh", "-c", command).CombinedOutput(); err != nil {
		t.Fatalf("proxy command: %v: %s", err, output)
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(data))
	want := []string{"__aws-ssm-proxy", "--target", server.CloudID, "--region", "eu-west-1", "--port", "2207", "--plugin", "/fixture/session-manager-plugin"}
	if !slices.Equal(got, want) {
		t.Fatalf("args=%q, want %q", got, want)
	}
}

func TestAWSDirectSSHTransportKeepsControlMasterDefault(t *testing.T) {
	server := awsTestServer("i-0123456789abcdef0", "cbx_abcdef123456", "direct", "us-west-2")
	target, err := sshTargetForAWSServer(core.Config{Provider: "aws", TargetOS: core.TargetLinux}, server, "203.0.113.10", false)
	if err != nil {
		t.Fatal(err)
	}
	if target.ProxyCommand != "" || target.ProxyCommandStatus || target.NoControlMaster {
		t.Fatalf("direct target changed: %#v", target)
	}
}

func TestAWSSSMProxyCommandQuotesProviderValues(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "not-run")
	executable := filepath.Join(dir, "crabbox cli")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	command := awsSSMProxyCommand(executable, "/fixture/plugin path", "i-test'; touch "+sentinel+"; 'x", "us-test-1'; false; '")
	if strings.Contains(command, "--profile") {
		t.Fatalf("proxy unexpectedly selected an AWS CLI profile: %q", command)
	}
	if output, err := exec.Command("sh", "-c", expandSSHProxyCommandForTest(command, "22")).CombinedOutput(); err != nil {
		t.Fatalf("proxy command failed: %v: %s", err, output)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("provider value escaped shell quoting: %v", err)
	}
}

func expandSSHProxyCommandForTest(command, port string) string {
	return strings.NewReplacer("%%", "%", "%p", port).Replace(command)
}

func TestAWSSSMResolveRebuildsPersistedProxy(t *testing.T) {
	installAWSSSMDependencies(t, "/fixture/aws")
	server := awsTestServer("i-0123456789abcdef0", "cbx_abcdef123456", "private", "eu-west-1")
	server.Labels["aws_ssh_transport"] = core.AWSSSHTransportSSM
	fake := &fakeAWSClient{servers: []core.Server{server}}
	previous := newAWSClient
	newAWSClient = func(context.Context, core.Config) (awsClient, error) { return fake, nil }
	t.Cleanup(func() { newAWSClient = previous })
	backend := NewAWSLeaseBackend(Provider{}.Spec(), core.Config{Provider: "aws", TargetOS: core.TargetLinux, AWSRegion: "eu-west-1"}, core.Runtime{Stderr: io.Discard}).(*awsLeaseBackend)
	lease, err := backend.Resolve(t.Context(), core.ResolveRequest{ID: server.CloudID})
	if err != nil {
		t.Fatal(err)
	}
	if lease.SSH.Host != server.CloudID || !strings.Contains(lease.SSH.ProxyCommand, "__aws-ssm-proxy") || !strings.Contains(lease.SSH.ProxyCommand, "eu-west-1") || !lease.SSH.ProxyCommandStatus {
		t.Fatalf("resolved SSH=%#v", lease.SSH)
	}
}

func TestAWSHistoricalUnlabelledLeaseRemainsDirect(t *testing.T) {
	server := awsTestServer("i-0123456789abcdef0", "cbx_abcdef123456", "historical", "eu-west-1")
	fake := &fakeAWSClient{servers: []core.Server{server}}
	previous := newAWSClient
	newAWSClient = func(context.Context, core.Config) (awsClient, error) { return fake, nil }
	t.Cleanup(func() { newAWSClient = previous })
	cfg := core.Config{Provider: "aws", TargetOS: core.TargetLinux, AWSRegion: "eu-west-1", AWSSSHTransport: core.AWSSSHTransportSSM}
	lease, err := NewAWSLeaseBackend(Provider{}.Spec(), cfg, core.Runtime{Stderr: io.Discard}).(*awsLeaseBackend).Resolve(t.Context(), core.ResolveRequest{ID: server.CloudID})
	if err != nil {
		t.Fatal(err)
	}
	if lease.SSH.Host != server.PublicNet.IPv4.IP || lease.SSH.ProxyCommand != "" || lease.SSH.AccessMetadata[awsCheckpointSSHTransportMetadata] != core.AWSSSHTransportDirect {
		t.Fatalf("historical lease transport changed: %#v", lease.SSH)
	}
}

func TestAWSSSMClaimRecoveryRebuildsProxyWhenLiveTagIsAbsent(t *testing.T) {
	installAWSSSMDependencies(t, "/fixture/aws")
	server := awsTestServer("i-0123456789abcdef0", "cbx_abcdef123456", "private", "eu-west-1")
	fake := &fakeAWSClient{servers: []core.Server{server}}
	previous := newAWSClient
	newAWSClient = func(context.Context, core.Config) (awsClient, error) { return fake, nil }
	t.Cleanup(func() { newAWSClient = previous })
	backend := NewAWSLeaseBackend(Provider{}.Spec(), core.Config{Provider: "aws", TargetOS: core.TargetLinux, AWSRegion: "us-east-1"}, core.Runtime{Stderr: io.Discard}).(*awsLeaseBackend)
	claim := core.LeaseClaim{
		LeaseID: server.Labels["lease"], CloudID: server.CloudID, Provider: "aws",
		Labels: map[string]string{"aws_region": "eu-west-1", "aws_ssh_transport": core.AWSSSHTransportSSM},
	}
	lease, err := backend.ResolveRunLeaseUnderClaim(t.Context(), core.ResolveRequest{}, claim)
	if err != nil {
		t.Fatal(err)
	}
	if lease.SSH.Host != server.CloudID || !strings.Contains(lease.SSH.ProxyCommand, "eu-west-1") {
		t.Fatalf("resolved SSH=%#v", lease.SSH)
	}
}

func TestAWSSSMDependenciesFailBeforeAWSCalls(t *testing.T) {
	previousLookPath := awsSSMLookPath
	awsSSMLookPath = func(name string) (string, error) {
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() { awsSSMLookPath = previousLookPath })
	called := false
	previousClient := newAWSClient
	newAWSClient = func(context.Context, core.Config) (awsClient, error) {
		called = true
		return nil, errors.New("unexpected AWS call")
	}
	t.Cleanup(func() { newAWSClient = previousClient })
	cfg := core.Config{Provider: "aws", TargetOS: core.TargetLinux, AWSRegion: "us-east-1", AWSSSHTransport: core.AWSSSHTransportSSM}
	_, err := NewAWSLeaseBackend(Provider{}.Spec(), cfg, core.Runtime{Stderr: io.Discard}).(*awsLeaseBackend).Acquire(t.Context(), core.AcquireRequest{})
	if err == nil || !strings.Contains(err.Error(), "session-manager-plugin") || called {
		t.Fatalf("error=%v AWSCalled=%t", err, called)
	}
}

func TestAWSSSMLocalWindowsFailsBeforeDependencyLookup(t *testing.T) {
	previousGOOS := awsSSMRuntimeGOOS
	previousLookPath := awsSSMLookPath
	awsSSMRuntimeGOOS = "windows"
	lookups := 0
	awsSSMLookPath = func(string) (string, error) {
		lookups++
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() {
		awsSSMRuntimeGOOS = previousGOOS
		awsSSMLookPath = previousLookPath
	})
	err := preflightAWSSSMTransport(core.Config{Provider: "aws", TargetOS: core.TargetLinux, AWSSSHTransport: core.AWSSSHTransportSSM})
	if err == nil || !strings.Contains(err.Error(), "local Windows") || lookups != 0 {
		t.Fatalf("error=%v lookups=%d", err, lookups)
	}
}

func TestAWSSSMCoordinatorAcquireFailsClosed(t *testing.T) {
	backend := NewAWSLeaseBackend(Provider{}.Spec(), core.Config{Provider: "aws", TargetOS: core.TargetLinux, AWSSSHTransport: core.AWSSSHTransportSSM}, core.Runtime{}).(*awsLeaseBackend)
	if err := backend.ValidateCoordinatorAcquire(); err == nil || !strings.Contains(err.Error(), "requires direct mode") {
		t.Fatalf("error=%v", err)
	}
}

func TestAWSSSMAcquireSkipsPublicIPWaitAndCIDRDiscovery(t *testing.T) {
	testutil.IsolateUserDirs(t)
	installAWSSSMDependencies(t, "/fixture/aws")
	fake := &fakeAWSClient{}
	restore := installFixedAWSTestClient(t, fake)
	defer restore()
	previousCIDRs := ensureAWSSSHCIDRs
	cidrCalls := 0
	ensureAWSSSHCIDRs = func(context.Context, *core.Config) { cidrCalls++ }
	t.Cleanup(func() { ensureAWSSSHCIDRs = previousCIDRs })
	cfg := fixedAWSTestConfig()
	cfg.AWSSSHTransport = core.AWSSSHTransportSSM
	lease, err := NewAWSLeaseBackend(Provider{}.Spec(), cfg, core.Runtime{Stderr: io.Discard}).(*awsLeaseBackend).Acquire(t.Context(), core.AcquireRequest{Keep: true})
	if err != nil {
		t.Fatal(err)
	}
	if fake.waitCalls != 0 || fake.readyWaitCalls != 1 || cidrCalls != 0 {
		t.Fatalf("publicWaits=%d visibilityWaits=%d cidrDiscoveries=%d", fake.waitCalls, fake.readyWaitCalls, cidrCalls)
	}
	if lease.SSH.Host != lease.Server.CloudID || lease.Server.Labels["aws_ssh_transport"] != core.AWSSSHTransportSSM || lease.SSH.ProxyCommand == "" {
		t.Fatalf("lease=%#v", lease)
	}
}

func TestAWSSSMFixedAcquireAndReplayKeepTransport(t *testing.T) {
	testutil.IsolateUserDirs(t)
	installAWSSSMDependencies(t, "/fixture/aws")
	fake := &fakeAWSClient{}
	restore := installFixedAWSTestClient(t, fake)
	defer restore()
	previousCIDRs := ensureAWSSSHCIDRs
	ensureAWSSSHCIDRs = func(context.Context, *core.Config) {}
	t.Cleanup(func() { ensureAWSSSHCIDRs = previousCIDRs })
	cfg := fixedAWSTestConfig()
	cfg.AWSSSHTransport = core.AWSSSHTransportSSM
	req := core.AcquireRequest{Keep: true, RequestedLeaseID: "cbx_abcdef123478", RequestedSlug: "private-fixed"}
	backend := NewAWSLeaseBackend(Provider{}.Spec(), cfg, core.Runtime{Stderr: io.Discard}).(*awsLeaseBackend)
	first, err := backend.Acquire(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewAWSLeaseBackend(Provider{}.Spec(), cfg, core.Runtime{Stderr: io.Discard}).(*awsLeaseBackend).Acquire(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if fake.createCalls != 1 || fake.waitCalls != 0 || fake.readyWaitCalls != 2 || first.Server.CloudID != replay.Server.CloudID || replay.SSH.Host != replay.Server.CloudID || replay.SSH.ProxyCommand == "" {
		t.Fatalf("creates=%d publicWaits=%d visibilityWaits=%d first=%#v replay=%#v", fake.createCalls, fake.waitCalls, fake.readyWaitCalls, first, replay)
	}
	direct := cfg
	direct.AWSSSHTransport = core.AWSSSHTransportDirect
	if _, err := NewAWSLeaseBackend(Provider{}.Spec(), direct, core.Runtime{Stderr: io.Discard}).(*awsLeaseBackend).Acquire(t.Context(), req); err == nil || !strings.Contains(err.Error(), "lease_id_conflict") {
		t.Fatalf("transport drift error=%v", err)
	}
}

func TestAWSSSMReleaseOnlyResolveDoesNotRequireCurrentTargetOrLocalDependencies(t *testing.T) {
	previous := awsSSMLookPath
	awsSSMLookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	t.Cleanup(func() { awsSSMLookPath = previous })
	server := awsTestServer("i-0123456789abcdef0", "cbx_abcdef123456", "private", "eu-west-1")
	server.Labels["aws_ssh_transport"] = core.AWSSSHTransportSSM
	for _, targetOS := range []string{core.TargetWindows, core.TargetMacOS} {
		t.Run(targetOS, func(t *testing.T) {
			target, err := sshTargetForAWSServer(core.Config{Provider: "aws", TargetOS: targetOS, AWSSSHTransport: core.AWSSSHTransportDirect}, server, "", true)
			if err != nil {
				t.Fatal(err)
			}
			if target.Host != server.CloudID || target.ProxyCommand != "" || target.AccessMetadata[awsCheckpointSSHTransportMetadata] != core.AWSSSHTransportSSM {
				t.Fatalf("target=%#v", target)
			}
		})
	}
}
