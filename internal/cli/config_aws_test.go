package cli

import "testing"

func TestAWSSSHTransportConfigDefaultsAndEnvironment(t *testing.T) {
	if got := AWSSSHTransportForConfig(Config{}); got != AWSSSHTransportDirect {
		t.Fatalf("default=%q", got)
	}
	clearConfigEnv(t)
	t.Setenv("CRABBOX_AWS_SSH_TRANSPORT", "ssm")
	cfg := baseConfig()
	if err := applyEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.AWSSSHTransport != AWSSSHTransportSSM || AWSSSHTransportForConfig(cfg) != AWSSSHTransportSSM {
		t.Fatalf("config=%#v", cfg)
	}
}

func TestNormalizeAWSSSHTransport(t *testing.T) {
	for _, test := range []struct {
		value string
		want  string
		ok    bool
	}{
		{value: "", want: AWSSSHTransportDirect, ok: true},
		{value: " DIRECT ", want: AWSSSHTransportDirect, ok: true},
		{value: " SSM ", want: AWSSSHTransportSSM, ok: true},
		{value: "proxy", ok: false},
	} {
		got, err := NormalizeAWSSSHTransport(test.value)
		if (err == nil) != test.ok || got != test.want {
			t.Fatalf("NormalizeAWSSSHTransport(%q)=(%q, %v), want (%q, ok=%t)", test.value, got, err, test.want, test.ok)
		}
	}
}
