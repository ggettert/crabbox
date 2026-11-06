package aws

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	core "github.com/openclaw/crabbox/internal/cli"
	"github.com/openclaw/crabbox/internal/providers/shared"
)

var awsSSMLookPath = exec.LookPath
var awsSSMRuntimeGOOS = runtime.GOOS
var awsSSMExecutable = os.Executable

const awsCheckpointSSHTransportMetadata = "aws.sshTransport"

func validateAWSSSHTransportConfig(cfg core.Config) error {
	transport, err := core.NormalizeAWSSSHTransport(cfg.AWSSSHTransport)
	if err != nil {
		return core.Exit(2, "%v", err)
	}
	if transport == core.AWSSSHTransportSSM && cfg.TargetOS != core.TargetLinux {
		return core.Exit(2, "provider=aws aws.sshTransport=ssm supports Linux targets only; Windows and macOS still require direct SSH")
	}
	return nil
}

func preflightAWSSSMTransport(cfg core.Config) error {
	if err := validateAWSSSHTransportConfig(cfg); err != nil {
		return err
	}
	if core.AWSSSHTransportForConfig(cfg) != core.AWSSSHTransportSSM {
		return nil
	}
	if awsSSMRuntimeGOOS == "windows" {
		return core.Exit(2, "provider=aws aws.sshTransport=ssm does not yet support a local Windows SSH client")
	}
	if _, err := awsSSMLookPath("session-manager-plugin"); err != nil {
		return core.Exit(3, "provider=aws aws.sshTransport=ssm requires session-manager-plugin on PATH: %v", err)
	}
	return nil
}

func awsSSHTransportForServer(_ core.Config, server core.Server) (string, error) {
	if value := strings.TrimSpace(server.Labels["aws_ssh_transport"]); value != "" {
		transport, err := core.NormalizeAWSSSHTransport(value)
		if err != nil {
			return "", core.Exit(4, "AWS instance %s has invalid persisted SSH transport %q", server.DisplayID(), value)
		}
		return transport, nil
	}
	return core.AWSSSHTransportDirect, nil
}

func annotateAWSSSHTransport(server core.Server, cfg core.Config) core.Server {
	if core.AWSSSHTransportForConfig(cfg) != core.AWSSSHTransportSSM {
		return server
	}
	if server.Labels == nil {
		server.Labels = map[string]string{}
	}
	server.Labels["aws_ssh_transport"] = core.AWSSSHTransportSSM
	return server
}

func awsSSMProxyCommand(executable, plugin, instanceID, region string) string {
	literalArgs := []string{
		executable, "__aws-ssm-proxy",
		"--target", instanceID,
		"--region", region,
		"--port",
	}
	quoted := make([]string, 0, len(literalArgs)+3)
	for _, arg := range literalArgs {
		quoted = append(quoted, shared.QuoteSSHProxyCommandWord(arg))
	}
	quoted = append(quoted, "%p")
	quoted = append(quoted, shared.QuoteSSHProxyCommandWord("--plugin"), shared.QuoteSSHProxyCommandWord(plugin))
	return strings.Join(quoted, " ")
}

func sshTargetForAWSServer(cfg core.Config, server core.Server, directHost string, releaseOnly bool) (core.SSHTarget, error) {
	transport, err := awsSSHTransportForServer(cfg, server)
	if err != nil {
		return core.SSHTarget{}, err
	}
	if transport != core.AWSSSHTransportSSM {
		target := core.SSHTargetFromConfig(cfg, directHost)
		target.AccessMetadata = map[string]string{awsCheckpointSSHTransportMetadata: core.AWSSSHTransportDirect}
		return target, nil
	}
	instanceID := strings.TrimSpace(server.CloudID)
	region := awsServerRegion(server)
	if region == "" {
		region = strings.TrimSpace(cfg.AWSRegion)
	}
	if instanceID == "" || region == "" {
		return core.SSHTarget{}, core.Exit(4, "AWS SSM SSH target requires an instance ID and region")
	}
	target := core.SSHTargetFromConfig(cfg, instanceID)
	target.AccessMetadata = map[string]string{awsCheckpointSSHTransportMetadata: core.AWSSSHTransportSSM}
	if releaseOnly {
		return target, nil
	}
	if cfg.TargetOS != core.TargetLinux {
		return core.SSHTarget{}, core.Exit(2, "provider=aws persisted SSM SSH transport supports Linux targets only")
	}
	ssmCfg := cfg
	ssmCfg.AWSSSHTransport = core.AWSSSHTransportSSM
	if err := preflightAWSSSMTransport(ssmCfg); err != nil {
		return core.SSHTarget{}, err
	}
	executable, err := awsSSMExecutable()
	if err != nil {
		return core.SSHTarget{}, fmt.Errorf("resolve Crabbox executable for SSM SSH transport: %w", err)
	}
	plugin, err := awsSSMLookPath("session-manager-plugin")
	if err != nil {
		return core.SSHTarget{}, fmt.Errorf("resolve Session Manager plugin for SSM SSH transport: %w", err)
	}
	target.ProxyCommand = awsSSMProxyCommand(executable, plugin, instanceID, region)
	target.ProxyCommandStatus = true
	target.NoControlMaster = true
	return target, nil
}
