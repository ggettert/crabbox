package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openclaw/crabbox/internal/cli"
)

const awsSSMProxyMainHelperEnvironment = "CRABBOX_TEST_AWS_SSM_PROXY_MAIN_HELPER"
const awsSSMProxyMainPluginEnvironment = "CRABBOX_TEST_AWS_SSM_PROXY_PLUGIN"

func TestAWSOwnedSSMProxyHiddenMain(t *testing.T) {
	if os.Getenv(awsSSMProxyMainHelperEnvironment) == "1" {
		os.Args = []string{
			"crabbox", "__aws-ssm-proxy",
			"--target", "i-0123456789abcdef0",
			"--region", "us-test-1",
			"--port", "2207",
			"--plugin", os.Getenv(awsSSMProxyMainPluginEnvironment),
		}
		os.Exit(run())
	}
	type request struct {
		target       string
		documentName string
		port         string
		sessionID    string
	}
	var mu sync.Mutex
	var requests []request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonSSM.StartSession":
			var input struct {
				Target       string              `json:"Target"`
				DocumentName string              `json:"DocumentName"`
				Parameters   map[string][]string `json:"Parameters"`
			}
			if err := json.Unmarshal(body, &input); err != nil {
				t.Error(err)
				http.Error(w, "decode", http.StatusBadRequest)
				return
			}
			mu.Lock()
			requests = append(requests, request{target: input.Target, documentName: input.DocumentName, port: input.Parameters["portNumber"][0]})
			mu.Unlock()
			_, _ = io.WriteString(w, `{"SessionId":"session-hidden-main","TokenValue":"hidden-main-secret-token","StreamUrl":"wss://fixture.invalid/hidden-main-secret"}`)
		case "AmazonSSM.TerminateSession":
			var input struct {
				SessionID string `json:"SessionId"`
			}
			if err := json.Unmarshal(body, &input); err != nil {
				t.Error(err)
				http.Error(w, "decode", http.StatusBadRequest)
				return
			}
			mu.Lock()
			requests = append(requests, request{sessionID: input.SessionID})
			mu.Unlock()
			_, _ = io.WriteString(w, `{"SessionId":"session-hidden-main"}`)
		default:
			t.Errorf("unexpected target %q body=%s", r.Header.Get("X-Amz-Target"), body)
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	statusDir := filepath.Join(dir, "status")
	if err := os.Mkdir(statusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(dir, "plugin-args")
	plugin := filepath.Join(dir, "session-manager-plugin")
	pluginScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsPath + "'\nprintf 'hidden-main-wire'\n"
	if err := os.WriteFile(plugin, []byte(pluginScript), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAWSOwnedSSMProxyHiddenMain$")
	cmd.Env = append(os.Environ(),
		awsSSMProxyMainHelperEnvironment+"=1",
		awsSSMProxyMainPluginEnvironment+"="+plugin,
		cli.ProxyCommandStatusEnvironment+"="+statusDir,
		"AWS_ENDPOINT_URL_SSM="+server.URL,
		"AWS_ACCESS_KEY_ID=fixture-access-key",
		"AWS_SECRET_ACCESS_KEY=fixture-secret-key",
		"AWS_EC2_METADATA_DISABLED=true",
	)
	stdout, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("hidden helper: %v stderr=%s", err, exitErr.Stderr)
		}
		t.Fatal(err)
	}
	if string(stdout) != "hidden-main-wire" {
		t.Fatalf("stdout=%q", stdout)
	}
	mu.Lock()
	got := append([]request(nil), requests...)
	mu.Unlock()
	if len(got) != 2 || got[0] != (request{target: "i-0123456789abcdef0", documentName: "AWS-StartSSHSession", port: "2207"}) || got[1].sessionID != "session-hidden-main" {
		t.Fatalf("SDK calls=%+v", got)
	}
	pluginArgs, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(pluginArgs, []byte("hidden-main-secret-token")) || !strings.Contains(string(pluginArgs), "AWS_SSM_START_SESSION_RESPONSE") {
		t.Fatalf("plugin args=%q", pluginArgs)
	}
	result, err := os.ReadFile(filepath.Join(statusDir, "result"))
	if err != nil || string(result) != "ok\n" {
		t.Fatalf("lifecycle result=%q err=%v", result, err)
	}
}

func TestAWSOwnedSSMProxyReadinessCleanupFailureStopsRetry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX owned-process fixture")
	}
	type request struct {
		target    string
		sessionID string
	}
	var mu sync.Mutex
	var requests []request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonSSM.StartSession":
			var input struct {
				Target string `json:"Target"`
			}
			if err := json.Unmarshal(body, &input); err != nil {
				t.Error(err)
				http.Error(w, "decode", http.StatusBadRequest)
				return
			}
			mu.Lock()
			requests = append(requests, request{target: input.Target})
			mu.Unlock()
			_, _ = io.WriteString(w, `{"SessionId":"session-readiness","TokenValue":"readiness-secret-token","StreamUrl":"wss://fixture.invalid/readiness-secret-stream"}`)
		case "AmazonSSM.TerminateSession":
			var input struct {
				SessionID string `json:"SessionId"`
			}
			if err := json.Unmarshal(body, &input); err != nil {
				t.Error(err)
				http.Error(w, "decode", http.StatusBadRequest)
				return
			}
			mu.Lock()
			requests = append(requests, request{sessionID: input.SessionID})
			mu.Unlock()
			w.Header().Set("X-Amzn-Errortype", "AccessDeniedException")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"__type":"AccessDeniedException","message":"private-cleanup-detail"}`)
		default:
			t.Errorf("unexpected target %q body=%s", r.Header.Get("X-Amz-Target"), body)
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	sshArgsPath := filepath.Join(dir, "ssh-args")
	statusModePath := filepath.Join(dir, "status-mode")
	pluginArgsPath := filepath.Join(dir, "plugin-args")
	pluginResponsePath := filepath.Join(dir, "plugin-response")
	plugin := filepath.Join(dir, "session-manager-plugin")
	pluginScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + pluginArgsPath + "'\nprintf '%s' \"$AWS_SSM_START_SESSION_RESPONSE\" > '" + pluginResponsePath + "'\nprintf 'failed to open data channel private-plugin-detail\\n' >&2\nexit 17\n"
	if err := os.WriteFile(plugin, []byte(pluginScript), 0o700); err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(dir, "ssh")
	sshScript := `#!/bin/sh
set -eu
printf '%s\n' "$@" > "$CRABBOX_TEST_SSH_ARGS"
proxy=
for arg in "$@"; do
  case "$arg" in ProxyCommand=*) proxy=${arg#ProxyCommand=} ;; esac
done
[ -n "$proxy" ]
stat -c %a "$CRABBOX_INTERNAL_PROXY_STATUS_DIR" > "$CRABBOX_TEST_STATUS_MODE"
sh -c "exec $proxy" </dev/null >/dev/null
exit 255
`
	if err := os.WriteFile(ssh, []byte(sshScript), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CRABBOX_TEST_SSH_ARGS", sshArgsPath)
	t.Setenv("CRABBOX_TEST_STATUS_MODE", statusModePath)
	t.Setenv(awsSSMProxyMainHelperEnvironment, "1")
	t.Setenv(awsSSMProxyMainPluginEnvironment, plugin)
	t.Setenv("AWS_ENDPOINT_URL_SSM", server.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "fixture-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture-secret-key")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	proxyCommand := shellQuoteTest(os.Args[0]) + " -test.run=^TestAWSOwnedSSMProxyHiddenMain$"
	target := cli.SSHTarget{
		User: "ubuntu", Host: "i-0123456789abcdef0", Port: "2207", TargetOS: "linux",
		NoControlMaster: true, DisableHostKeyChecking: true,
		ProxyCommand: proxyCommand, ProxyCommandStatus: true,
	}
	var progress bytes.Buffer
	err := cli.WaitForSSHReady(t.Context(), &target, &progress, "bootstrap", 10*time.Second)
	if err == nil {
		t.Fatal("readiness unexpectedly succeeded")
	}
	message := err.Error() + progress.String()
	for _, want := range []string{"class=lifecycle_cleanup", "code=AccessDeniedException", "observed=data_channel"} {
		if !strings.Contains(message, want) {
			t.Fatalf("readiness error missing %q: %s", want, message)
		}
	}
	for _, forbidden := range []string{"readiness-secret-token", "readiness-secret-stream", "private-cleanup-detail", "private-plugin-detail"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("readiness diagnostics leaked %q: %s", forbidden, message)
		}
	}

	mu.Lock()
	gotRequests := append([]request(nil), requests...)
	mu.Unlock()
	if len(gotRequests) != 2 || gotRequests[0].target != target.Host || gotRequests[1].sessionID != "session-readiness" {
		t.Fatalf("SDK requests=%+v, want exactly one start then one terminate", gotRequests)
	}
	sshArgs, err := os.ReadFile(sshArgsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ProxyCommand=" + proxyCommand, "ControlMaster=no", "ControlPath=none", "ControlPersist=no"} {
		if !bytes.Contains(sshArgs, []byte(want)) {
			t.Fatalf("SSH args missing %q: %s", want, sshArgs)
		}
	}
	if bytes.Contains(sshArgs, []byte("readiness-secret-token")) || bytes.Contains(sshArgs, []byte("readiness-secret-stream")) {
		t.Fatalf("SSM response appeared in SSH arguments: %s", sshArgs)
	}
	statusMode, err := os.ReadFile(statusModePath)
	if err != nil || strings.TrimSpace(string(statusMode)) != "700" {
		t.Fatalf("status mode=%q err=%v", statusMode, err)
	}
	pluginArgs, err := os.ReadFile(pluginArgsPath)
	if err != nil {
		t.Fatal(err)
	}
	pluginResponse, err := os.ReadFile(pluginResponsePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pluginArgs, []byte("AWS_SSM_START_SESSION_RESPONSE")) || bytes.Contains(pluginArgs, []byte("readiness-secret-token")) {
		t.Fatalf("plugin argv contract=%q", pluginArgs)
	}
	if !bytes.Contains(pluginResponse, []byte("readiness-secret-token")) || !bytes.Contains(pluginResponse, []byte("readiness-secret-stream")) {
		t.Fatalf("plugin response environment=%q", pluginResponse)
	}
}

func shellQuoteTest(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
