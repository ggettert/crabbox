package cli

import (
	"fmt"
	"strings"
)

const (
	AWSSSHTransportDirect = "direct"
	AWSSSHTransportSSM    = "ssm"
)

func NormalizeAWSSSHTransport(value string) (string, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(value)); normalized {
	case "", AWSSSHTransportDirect:
		return AWSSSHTransportDirect, nil
	case AWSSSHTransportSSM:
		return AWSSSHTransportSSM, nil
	default:
		return "", fmt.Errorf("aws.sshTransport must be %q or %q, got %q", AWSSSHTransportDirect, AWSSSHTransportSSM, value)
	}
}

func AWSSSHTransportForConfig(cfg Config) string {
	transport, err := NormalizeAWSSSHTransport(cfg.AWSSSHTransport)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(cfg.AWSSSHTransport))
	}
	return transport
}

func awsUsesSSMSSHTransport(cfg Config) bool {
	return AWSSSHTransportForConfig(cfg) == AWSSSHTransportSSM
}
