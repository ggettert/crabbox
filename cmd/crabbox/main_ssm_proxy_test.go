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
	"strings"
	"sync"
	"testing"

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
