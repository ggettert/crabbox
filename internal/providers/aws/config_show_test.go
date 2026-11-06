package aws

import (
	"testing"

	core "github.com/openclaw/crabbox/internal/cli"
)

func TestAWSConfigShowIncludesSSHTransport(t *testing.T) {
	for _, test := range []struct {
		value string
		want  string
	}{
		{want: core.AWSSSHTransportDirect},
		{value: core.AWSSSHTransportSSM, want: core.AWSSSHTransportSSM},
	} {
		section := (Provider{}).ConfigShowSection(core.Config{AWSSSHTransport: test.value})
		found := false
		for _, field := range section.Fields {
			if field.JSONName == "sshTransport" {
				found = true
				if field.JSONValue != test.want || field.TextValue != test.want {
					t.Fatalf("field=%#v want=%q", field, test.want)
				}
			}
		}
		if !found {
			t.Fatal("sshTransport field missing")
		}
	}
}
