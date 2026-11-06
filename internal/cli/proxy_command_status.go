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
			return errors.New("proxy command exited without reporting lifecycle status")
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
				return errors.New(strings.TrimSpace(strings.TrimPrefix(result, "error:")))
			default:
				return errors.New("proxy command returned an invalid lifecycle result")
			}
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read proxy command lifecycle result: %w", err)
		}
		if time.Now().After(deadline) {
			return errors.New("proxy command did not report lifecycle cleanup before the grace period expired")
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
