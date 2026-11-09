package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var proxyCommandStatusGrace = 6 * time.Second

type proxyCommandStatus struct {
	dir         string
	cleanupOnce sync.Once
	cleanupErr  error
}

type proxyCommandFailureClass string

const (
	proxyCommandFailureLifecycle        proxyCommandFailureClass = "lifecycle"
	proxyCommandFailureLifecycleCleanup proxyCommandFailureClass = "lifecycle_cleanup"
	proxyCommandFailureUnknownOutcome   proxyCommandFailureClass = "unknown_session_outcome"
	proxyCommandFailurePermissionDenied proxyCommandFailureClass = "api_permission_denied"
)

type proxyCommandStatusError struct {
	class proxyCommandFailureClass
	code  string
}

func (e *proxyCommandStatusError) Error() string {
	message := "SSH proxy failed class=" + string(e.class)
	if e.code != "" {
		message += " code=" + e.code
	}
	return message
}

func (e *proxyCommandStatusError) readinessFatal() bool {
	switch e.class {
	case proxyCommandFailureLifecycleCleanup, proxyCommandFailureUnknownOutcome, proxyCommandFailurePermissionDenied:
		return true
	default:
		return false
	}
}

func classifyProxyCommandStatusError(result string) *proxyCommandStatusError {
	switch {
	case strings.Contains(result, "terminate owned SSM session"):
		return &proxyCommandStatusError{class: proxyCommandFailureLifecycleCleanup, code: safeProxyCommandStatusCode(result)}
	case strings.Contains(result, "AWS API error AccessDeniedException"):
		return &proxyCommandStatusError{class: proxyCommandFailurePermissionDenied, code: "AccessDeniedException"}
	case strings.Contains(result, "SSM session start outcome is unknown"):
		return &proxyCommandStatusError{class: proxyCommandFailureUnknownOutcome}
	default:
		return &proxyCommandStatusError{class: proxyCommandFailureLifecycle}
	}
}

func safeProxyCommandStatusCode(result string) string {
	if strings.Contains(result, "context deadline exceeded") {
		return "deadline_exceeded"
	}
	const marker = "AWS API error "
	index := strings.Index(result, marker)
	if index < 0 {
		return "failed"
	}
	code := strings.Fields(result[index+len(marker):])
	if len(code) == 0 || !isSafeProxyCommandStatusCode(code[0]) {
		return "failed"
	}
	return code[0]
}

func isSafeProxyCommandStatusCode(code string) bool {
	if len(code) == 0 || len(code) > 64 {
		return false
	}
	for _, character := range code {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func (s *proxyCommandStatus) prepare(cmd *exec.Cmd) error {
	if s == nil || s.dir != "" {
		return nil
	}
	dir, err := os.MkdirTemp("", "crabbox-proxy-status-*")
	if err != nil {
		return fmt.Errorf("create private proxy status directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("secure private proxy status directory: %w", err)
	}
	s.dir = dir
	cmd.Env = childEnvironmentWithout(cmd.Environ(), ProxyCommandStatusEnvironment)
	cmd.Env = append(cmd.Env, ProxyCommandStatusEnvironment+"="+dir)
	return nil
}

func (s *proxyCommandStatus) started() bool {
	if s == nil || s.dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(s.dir, "started"))
	return err == nil
}

func (s *proxyCommandStatus) wait(requireResult bool) error {
	if s == nil || s.dir == "" {
		return nil
	}
	startedDeadline := time.Now().Add(100 * time.Millisecond)
	for !s.started() && time.Now().Before(startedDeadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.started() {
		if requireResult {
			return &proxyCommandStatusError{class: proxyCommandFailureUnknownOutcome, code: "missing_start_marker"}
		}
		return nil
	}
	resultPath := filepath.Join(s.dir, "result")
	deadline := time.Now().Add(proxyCommandStatusGrace)
	for {
		data, err := os.ReadFile(resultPath)
		if err == nil {
			result := strings.TrimSpace(string(data))
			switch {
			case result == "ok":
				return nil
			case strings.HasPrefix(result, "error:"):
				return classifyProxyCommandStatusError(strings.TrimSpace(strings.TrimPrefix(result, "error:")))
			default:
				return &proxyCommandStatusError{class: proxyCommandFailureUnknownOutcome, code: "invalid_result"}
			}
		}
		if !errors.Is(err, os.ErrNotExist) {
			return &proxyCommandStatusError{class: proxyCommandFailureUnknownOutcome, code: "result_unreadable"}
		}
		if time.Now().After(deadline) {
			return &proxyCommandStatusError{class: proxyCommandFailureLifecycleCleanup, code: "result_missing"}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *proxyCommandStatus) cleanup() error {
	if s == nil {
		return nil
	}
	s.cleanupOnce.Do(func() {
		if s.dir != "" {
			s.cleanupErr = os.RemoveAll(s.dir)
		}
	})
	return s.cleanupErr
}
