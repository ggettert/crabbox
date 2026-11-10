//go:build darwin || linux

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWorkspaceOwnerPOSIXCancelFencesAndQuiescesExactGroup(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is required for dedicated cancellation geometry")
	}
	home := t.TempDir()
	key := "cancel-quiescence"
	token := strings.Repeat("a", 64)
	req := func(action workspaceOwnerAction) workspaceOwnerRemoteRequest {
		return workspaceOwnerRemoteRequest{Action: action, Key: key, Token: token, TTL: time.Minute}
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerAcquire))); err != nil || out != "ACQUIRED" {
		t.Fatalf("acquire out=%q err=%v", out, err)
	}
	started, bad := filepath.Join(home, "STARTED"), filepath.Join(home, "BAD")
	witness := exec.Command("/bin/sh", "-c", remoteWorkspaceOwnerPOSIXWitness(key, token, "printf started > "+shellQuote(started)+"; sleep 30; printf bad > "+shellQuote(bad)))
	witness.Env = append(os.Environ(), "HOME="+home)
	var witnessOutput bytes.Buffer
	witness.Stdout, witness.Stderr = &witnessOutput, &witnessOutput
	if err := witness.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = witness.Process.Kill()
			t.Fatalf("witness did not start output=%q err=%v", witnessOutput.String(), witness.Wait())
		}
		time.Sleep(10 * time.Millisecond)
	}
	childPath := filepath.Join(home, ".crabbox", "workspace-owners", key+".child")
	waitForWorkspaceOwnerTestFile(t, childPath)
	lines, err := os.ReadFile(childPath)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(strings.TrimSpace(string(lines)), "\n")
	if len(fields) != 5 || fields[0] != fields[2] || fields[0] != fields[3] {
		t.Fatalf("witness metadata=%q", lines)
	}
	unrelated := exec.Command("setsid", "sleep", "30")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unrelated.Process.Kill(); _ = unrelated.Wait() })
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerCancel))); err != nil || out != "CANCELED" {
		t.Fatalf("cancel out=%q err=%v", out, err)
	}
	_ = witness.Wait()
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatalf("canceled workload reached BAD: %v", err)
	}
	pid, _ := strconv.Atoi(fields[0])
	if err := syscall.Kill(pid, 0); err == nil {
		stat, _ := exec.Command("ps", "-o", "stat=", "-p", fields[0]).Output()
		if !strings.HasPrefix(strings.TrimSpace(string(stat)), "Z") {
			t.Fatalf("witness leader still live pid=%d stat=%q", pid, stat)
		}
	}
	if err := unrelated.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated process was signaled: %v", err)
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerRelease))); err != nil || out != "RELEASED" {
		t.Fatalf("release out=%q err=%v", out, err)
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerAcquire))); err != nil || out != "ACQUIRED" {
		t.Fatalf("immediate reacquire out=%q err=%v", out, err)
	}
	next := filepath.Join(home, "NEXT_OK")
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIXWitness(key, token, "printf next > "+shellQuote(next))); err != nil || out != "" {
		t.Fatalf("next command out=%q err=%v", out, err)
	}
	if _, err := os.Stat(next); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceOwnerPOSIXCancelUsesPortableGroupSignalSyntax(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is required for dedicated cancellation geometry")
	}
	home := t.TempDir()
	key := "cancel-portable-signal"
	token := strings.Repeat("d", 64)
	req := func(action workspaceOwnerAction) workspaceOwnerRemoteRequest {
		return workspaceOwnerRemoteRequest{Action: action, Key: key, Token: token, TTL: time.Minute}
	}
	run := func(script string) (string, error) {
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Env = append(os.Environ(), "HOME="+home)
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if out, err := run(remoteWorkspaceOwnerPOSIX(req(workspaceOwnerAcquire))); err != nil || out != "ACQUIRED" {
		t.Fatalf("acquire out=%q err=%v", out, err)
	}
	started := filepath.Join(home, "STARTED")
	witness := exec.Command("/bin/sh", "-c", remoteWorkspaceOwnerPOSIXWitness(key, token, "trap '' TERM; printf started > "+shellQuote(started)+"; sleep 30"))
	witness.Env = append(os.Environ(), "HOME="+home)
	var witnessOutput bytes.Buffer
	witness.Stdout, witness.Stderr = &witnessOutput, &witnessOutput
	if err := witness.Start(); err != nil {
		t.Fatal(err)
	}
	childPath := filepath.Join(home, ".crabbox", "workspace-owners", key+".child")
	t.Cleanup(func() {
		if metadata, err := os.ReadFile(childPath); err == nil {
			fields := strings.Split(strings.TrimSpace(string(metadata)), "\n")
			if len(fields) == 5 && fields[0] == fields[2] && fields[0] == fields[3] {
				if pid, err := strconv.Atoi(fields[0]); err == nil {
					_ = syscall.Kill(-pid, syscall.SIGKILL)
				}
			}
		}
		_ = witness.Process.Kill()
		_ = witness.Wait()
	})
	waitForWorkspaceOwnerTestFile(t, started)
	waitForWorkspaceOwnerTestFile(t, childPath)
	if out, err := run(remoteWorkspaceOwnerPOSIX(req(workspaceOwnerCancel))); err != nil || out != "CANCELED" {
		t.Fatalf("cancel out=%q err=%v witness=%q", out, err, witnessOutput.String())
	}
}

func TestWorkspaceOwnerPOSIXCancelBeforePublicationFencesRegistrar(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is required for registrar race geometry")
	}
	home := t.TempDir()
	key, token := "cancel-race", strings.Repeat("b", 64)
	req := func(action workspaceOwnerAction) workspaceOwnerRemoteRequest {
		return workspaceOwnerRemoteRequest{Action: action, Key: key, Token: token, TTL: time.Minute}
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerAcquire))); err != nil || out != "ACQUIRED" {
		t.Fatalf("acquire out=%q err=%v", out, err)
	}
	paused := filepath.Join(home, "registrar-paused")
	resume := filepath.Join(home, "registrar-resume")
	marker := filepath.Join(home, "late-workload")
	script := remoteWorkspaceOwnerPOSIXWitnessScript(key, token, "touch "+shellQuote(marker), "")
	pause := `printf paused > "$HOME/registrar-paused"; while [ ! -f "$HOME/registrar-resume" ]; do sleep .01; done
run_owner_gate `
	script = strings.Replace(script, "run_owner_gate ", pause, 1)
	registrar := exec.Command("/bin/sh", "-c", script)
	registrar.Env = append(os.Environ(), "HOME="+home)
	var registrarOutput bytes.Buffer
	registrar.Stdout, registrar.Stderr = &registrarOutput, &registrarOutput
	if err := registrar.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registrar.Process.Kill(); _ = registrar.Wait() })
	waitForWorkspaceOwnerTestFile(t, paused)
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerCancel))); err != nil || out != "CANCELED" {
		t.Fatalf("cancel out=%q err=%v", out, err)
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerRelease))); err != nil || out != "RELEASED" {
		t.Fatalf("release out=%q err=%v", out, err)
	}
	if err := os.WriteFile(resume, []byte("resume"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := registrar.Wait(); err == nil {
		t.Fatalf("fenced registrar succeeded output=%q", registrarOutput.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("fenced workload executed: %v", err)
	}
	child := filepath.Join(home, ".crabbox", "workspace-owners", key+".child")
	if _, err := os.Stat(child); !os.IsNotExist(err) {
		t.Fatalf("fenced registrar published child: %v", err)
	}
	freshToken := strings.Repeat("f", 64)
	freshReq := func(action workspaceOwnerAction) workspaceOwnerRemoteRequest {
		return workspaceOwnerRemoteRequest{Action: action, Key: key, Token: freshToken, TTL: time.Minute}
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(freshReq(workspaceOwnerAcquire))); err != nil || out != "ACQUIRED" {
		t.Fatalf("fresh acquire out=%q err=%v", out, err)
	}
	next := filepath.Join(home, "NEXT_OK")
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIXWitness(key, freshToken, "printf next > "+shellQuote(next))); err != nil || out != "" {
		t.Fatalf("next command out=%q err=%v", out, err)
	}
	if _, err := os.Stat(next); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceOwnerPOSIXCancelRejectsUnverifiableWitnessesWithoutSignals(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]string) []string
	}{
		{name: "legacy", mutate: func(lines []string) []string { return lines[:2] }},
		{name: "weak ps identity", mutate: func(lines []string) []string { lines[4] = "ps:" + lines[1]; return lines }},
		{name: "start mismatch", mutate: func(lines []string) []string { lines[4] = "linux:0"; return lines }},
		{name: "pgid mismatch", mutate: func(lines []string) []string { lines[2] = "1"; return lines }},
		{name: "sid mismatch", mutate: func(lines []string) []string { lines[3] = "1"; return lines }},
		{name: "nonleader", mutate: func(lines []string) []string { lines[0] = strconv.Itoa(os.Getpid()); return lines }},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			key, token := "cancel-reject", strings.Repeat("c", 64)
			req := func(action workspaceOwnerAction) workspaceOwnerRemoteRequest {
				return workspaceOwnerRemoteRequest{Action: action, Key: key, Token: token, TTL: time.Minute}
			}
			if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerAcquire))); err != nil || out != "ACQUIRED" {
				t.Fatalf("acquire out=%q err=%v", out, err)
			}
			victim := exec.Command("setsid", "sleep", "30")
			if err := victim.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = victim.Process.Kill(); _ = victim.Wait() }()
			pid := strconv.Itoa(victim.Process.Pid)
			identityOut, _ := exec.Command("ps", "-o", "lstart=", "-p", pid).Output()
			identity := strings.TrimSpace(strings.Join(strings.Fields(string(identityOut)), " "))
			stat, err := os.ReadFile("/proc/" + pid + "/stat")
			if err != nil {
				t.Skip("strong Linux identity unavailable")
			}
			start, ok := linuxProcStartIdentity(stat)
			if !ok {
				t.Fatalf("malformed proc stat: %q", stat)
			}
			lines := []string{pid, identity, pid, pid, start}
			lines = test.mutate(lines)
			child := filepath.Join(home, ".crabbox", "workspace-owners", key+".child")
			if err := os.WriteFile(child, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerCancel)))
			if err == nil || out != "AMBIGUOUS" {
				t.Fatalf("cancel out=%q err=%v", out, err)
			}
			if err := victim.Process.Signal(syscall.Signal(0)); err != nil {
				t.Fatalf("victim was signaled: %v", err)
			}
			if _, err := os.Stat(child); err != nil {
				t.Fatalf("witness removed: %v", err)
			}
		})
	}
}

func TestWorkspaceOwnerPOSIXRetainsDedicatedGroupAfterLeaderExit(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is required for dedicated cancellation geometry")
	}
	home := t.TempDir()
	key, token := "cancel-retained-group", strings.Repeat("6", 64)
	req := func(action workspaceOwnerAction, requestToken string, ttl time.Duration) workspaceOwnerRemoteRequest {
		return workspaceOwnerRemoteRequest{Action: action, Key: key, Token: requestToken, TTL: ttl}
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerAcquire, token, time.Minute))); err != nil || out != "ACQUIRED" {
		t.Fatalf("acquire out=%q err=%v", out, err)
	}
	memberPath := filepath.Join(home, "member.pid")
	started := filepath.Join(home, "STARTED")
	bad := filepath.Join(home, "BAD")
	command := "trap 'exit 0' TERM; sh -c 'trap \"\" TERM; while :; do sleep 1; done' & " +
		"printf '%s' $! > " + shellQuote(memberPath) + "; printf started > " + shellQuote(started) +
		"; wait; printf bad > " + shellQuote(bad)
	witness := exec.Command("/bin/sh", "-c", remoteWorkspaceOwnerPOSIXWitness(key, token, command))
	witness.Env = append(os.Environ(), "HOME="+home)
	var witnessOutput bytes.Buffer
	witness.Stdout, witness.Stderr = &witnessOutput, &witnessOutput
	if err := witness.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = witness.Process.Kill(); _ = witness.Wait() })
	waitForWorkspaceOwnerTestFile(t, started)
	waitForWorkspaceOwnerTestFile(t, memberPath)
	memberBytes, err := os.ReadFile(memberPath)
	if err != nil {
		t.Fatal(err)
	}
	memberPID, err := strconv.Atoi(strings.TrimSpace(string(memberBytes)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(memberPID, syscall.SIGKILL) })
	unrelated := exec.Command("setsid", "sleep", "30")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unrelated.Process.Kill(); _ = unrelated.Wait() })
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerCancel, token, time.Minute))); err == nil || out != "AMBIGUOUS" {
		t.Fatalf("cancel out=%q err=%v", out, err)
	}
	time.Sleep(100 * time.Millisecond)
	child := filepath.Join(home, ".crabbox", "workspace-owners", key+".child")
	if _, err := os.Stat(child); err != nil {
		t.Fatalf("wrapper clear removed child: %v", err)
	}
	metadataBytes, err := os.ReadFile(child)
	if err != nil {
		t.Fatal(err)
	}
	metadata := strings.Split(strings.TrimSpace(string(metadataBytes)), "\n")
	if len(metadata) != 5 {
		t.Fatalf("metadata=%q", metadataBytes)
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatalf("leader reached BAD: %v", err)
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerInspect, token, time.Minute))); err != nil || out != "CHILD" {
		t.Fatalf("inspect out=%q err=%v", out, err)
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerRelease, token, time.Minute))); err == nil || out != "CHILD" {
		t.Fatalf("release out=%q err=%v", out, err)
	}
	state := filepath.Join(home, ".crabbox", "workspace-owners", key+".owner")
	if err := os.WriteFile(state, []byte("v1\n"+token+"\n1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	freshToken := strings.Repeat("7", 64)
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerAcquire, freshToken, time.Minute))); err != nil || out != "CHILD" {
		t.Fatalf("expired acquire out=%q err=%v", out, err)
	}
	if err := unrelated.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated process was signaled: %v", err)
	}
	if err := syscall.Kill(memberPID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitForGroupQuiescence(t, metadata[2], metadata[3])
	_ = witness.Wait()
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerRelease, token, time.Minute))); err != nil || out != "RELEASED" {
		t.Fatalf("release after quiescence out=%q err=%v", out, err)
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerAcquire, freshToken, time.Minute))); err != nil || out != "ACQUIRED" {
		t.Fatalf("fresh acquire out=%q err=%v", out, err)
	}
	next := filepath.Join(home, "NEXT_OK")
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIXWitness(key, freshToken, "printf next > "+shellQuote(next))); err != nil || out != "" {
		t.Fatalf("next command out=%q err=%v", out, err)
	}
	if _, err := os.Stat(next); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceOwnerPOSIXCancelExecWithSpacesInComm(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is required for dedicated cancellation geometry")
	}
	home := t.TempDir()
	executable := filepath.Join(home, "sleep with spaces")
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, data, 0o755); err != nil {
		t.Fatal(err)
	}
	key, token := "cancel-spaced-comm", strings.Repeat("8", 64)
	req := func(action workspaceOwnerAction) workspaceOwnerRemoteRequest {
		return workspaceOwnerRemoteRequest{Action: action, Key: key, Token: token, TTL: time.Minute}
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerAcquire))); err != nil || out != "ACQUIRED" {
		t.Fatalf("acquire out=%q err=%v", out, err)
	}
	started := filepath.Join(home, "STARTED")
	witness := exec.Command("/bin/sh", "-c", remoteWorkspaceOwnerPOSIXWitness(key, token, "printf started > "+shellQuote(started)+"; exec "+shellQuote(executable)+" 30"))
	witness.Env = append(os.Environ(), "HOME="+home)
	var witnessOutput bytes.Buffer
	witness.Stdout, witness.Stderr = &witnessOutput, &witnessOutput
	if err := witness.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = witness.Process.Kill(); _ = witness.Wait() })
	waitForWorkspaceOwnerTestFile(t, started)
	child := filepath.Join(home, ".crabbox", "workspace-owners", key+".child")
	waitForWorkspaceOwnerTestFile(t, child)
	metadataBytes, err := os.ReadFile(child)
	if err != nil {
		t.Fatal(err)
	}
	metadata := strings.Split(strings.TrimSpace(string(metadataBytes)), "\n")
	if len(metadata) != 5 {
		t.Fatalf("metadata=%q", metadataBytes)
	}
	stat, err := os.ReadFile("/proc/" + metadata[0] + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	start, ok := linuxProcStartIdentity(stat)
	if !ok || start != metadata[4] {
		t.Fatalf("recorded start=%q live start=%q stat=%q", metadata[4], start, stat)
	}
	unrelated := exec.Command("setsid", "sleep", "30")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unrelated.Process.Kill(); _ = unrelated.Wait() })
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerCancel))); err != nil || out != "CANCELED" {
		t.Fatalf("cancel out=%q err=%v", out, err)
	}
	_ = witness.Wait()
	if err := unrelated.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated process was signaled: %v", err)
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerRelease))); err != nil || out != "RELEASED" {
		t.Fatalf("release out=%q err=%v", out, err)
	}
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(req(workspaceOwnerAcquire))); err != nil || out != "ACQUIRED" {
		t.Fatalf("reacquire out=%q err=%v", out, err)
	}
	next := filepath.Join(home, "NEXT_OK")
	if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIXWitness(key, token, "printf next > "+shellQuote(next))); err != nil || out != "" {
		t.Fatalf("next command out=%q err=%v", out, err)
	}
	if _, err := os.Stat(next); err != nil {
		t.Fatal(err)
	}
}

func linuxProcStartIdentity(stat []byte) (string, bool) {
	closing := bytes.LastIndex(stat, []byte(") "))
	if closing < 0 {
		return "", false
	}
	fields := strings.Fields(string(stat[closing+2:]))
	if len(fields) < 20 || fields[19] == "" || strings.Trim(fields[19], "0123456789") != "" {
		return "", false
	}
	return "linux:" + fields[19], true
}

func waitForGroupQuiescence(t *testing.T, pgid, sid string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		output, err := exec.Command("ps", "-e", "-o", "pgid=", "-o", "sid=", "-o", "stat=").Output()
		if err != nil {
			t.Fatal(err)
		}
		live := false
		for _, row := range strings.Split(string(output), "\n") {
			fields := strings.Fields(row)
			if len(fields) >= 3 && fields[0] == pgid && fields[1] == sid && !strings.HasPrefix(fields[2], "Z") {
				live = true
				break
			}
		}
		if !live {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("group %s session %s did not quiesce", pgid, sid)
}

type workspaceOwnerStartedWriter struct {
	started chan struct{}
	data    strings.Builder
}

func (w *workspaceOwnerStartedWriter) Write(data []byte) (int, error) {
	_, _ = w.data.Write(data)
	if strings.Contains(w.data.String(), "STARTED") {
		select {
		case <-w.started:
		default:
			close(w.started)
		}
	}
	return len(data), nil
}

func TestWorkspaceOwnerCancellationOverRealOpenSSHAllowsImmediateReuse(t *testing.T) {
	if testing.Short() {
		t.Skip("real OpenSSH regression")
	}
	target, stop := startWorkspaceOwnerRootlessSSHD(t)
	defer stop()
	for _, proxy := range []bool{false, true} {
		name := "direct"
		probeTarget := target
		if proxy {
			name = "fake-proxy-route"
			probeTarget.SSHConfigProxy = true
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancelTest := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancelTest()
			transport := sshWorkspaceOwnerTransport{target: probeTarget}
			owner, err := acquireWorkspaceOwnerWithTransport(ctx, probeTarget, "cbx_cancel_real_"+name, io.Discard, transport, 10*time.Second, 20*time.Second, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			unrelated, err := runSSHOutput(ctx, probeTarget, "setsid /bin/sh -c 'exec sleep 30' >/dev/null 2>&1 < /dev/null & printf '%s' $!")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = runSSHQuiet(context.Background(), probeTarget, "kill "+unrelated+" 2>/dev/null || true") }()
			commandCtx, cancelCommand := context.WithCancel(contextWithWorkspaceOwner(ctx, owner))
			writer := &workspaceOwnerStartedWriter{started: make(chan struct{})}
			done := make(chan error, 1)
			go func() {
				_, runErr := executeSSHWithRetirement(commandCtx, &probeTarget, "printf STARTED; trap 'exit 0' TERM; sleep 30; printf BAD", nil, 0, sshCommandLimit{}, "10", "1", writer, writer)
				done <- runErr
			}()
			select {
			case <-writer.started:
			case <-ctx.Done():
				t.Fatal("witnessed command did not start")
			}
			child, err := runSSHOutput(ctx, probeTarget, "cat \"$HOME/.crabbox/workspace-owners/"+owner.key+".child\"")
			if err != nil {
				t.Fatal(err)
			}
			metadata := strings.Split(strings.TrimSpace(child), "\n")
			if len(metadata) != 5 || metadata[0] != metadata[2] || metadata[0] != metadata[3] {
				t.Fatalf("non-dedicated witness metadata=%q", child)
			}
			cancelCommand()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel error=%v output=%q", err, writer.data.String())
			}
			if strings.Contains(writer.data.String(), "BAD") {
				t.Fatalf("remote workload continued after cancellation: %q", writer.data.String())
			}
			if err := runSSHQuiet(ctx, probeTarget, "kill -0 "+unrelated); err != nil {
				t.Fatalf("unrelated remote process did not survive: %v", err)
			}
			if err := owner.Close(ctx); err != nil {
				t.Fatalf("ordinary owner release: %v", err)
			}
			nextOwner, err := acquireWorkspaceOwnerWithTransport(ctx, probeTarget, "cbx_cancel_real_"+name, io.Discard, transport, 10*time.Second, 20*time.Second, 5*time.Second)
			if err != nil {
				t.Fatalf("immediate owner reuse: %v", err)
			}
			var next strings.Builder
			if err := executeSSH(contextWithWorkspaceOwner(ctx, nextOwner), &probeTarget, "printf NEXT_OK", nil, 0, 0, "10", "1", &next, io.Discard); err != nil || next.String() != "NEXT_OK" {
				t.Fatalf("next command output=%q err=%v", next.String(), err)
			}
			if err := nextOwner.Close(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkspaceOwnerCancellationFromCLIProcessAllowsImmediateReuse(t *testing.T) {
	if testing.Short() {
		t.Skip("real OpenSSH CLI regression")
	}
	target, stop := startWorkspaceOwnerRootlessSSHD(t)
	defer stop()
	binary, err := builtCLITestBinary()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	leaseID := "static_cli_cancel_" + strconv.Itoa(os.Getpid()) + "_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	workRoot := filepath.Join(root, "remote-work")
	baseArgs := []string{
		"run", "--provider", "ssh", "--target", "linux",
		"--static-host", target.Host, "--static-user", target.User, "--static-port", target.Port,
		"--static-work-root", workRoot, "--static-no-control-master",
		"--no-sync", "--no-hydrate", "--keep",
	}
	environment := append(os.Environ(),
		"HOME="+root,
		"XDG_CONFIG_HOME="+filepath.Join(root, "config"),
		"XDG_STATE_HOME="+filepath.Join(root, "state"),
		"XDG_CACHE_HOME="+filepath.Join(root, "cache"),
		"CRABBOX_CONFIG="+filepath.Join(root, "missing.yaml"),
		"CRABBOX_SSH_KEY="+target.Key,
		"CRABBOX_STATIC_ID="+leaseID,
	)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	stopArgs := []string{
		"stop", "--provider", "ssh", "--target", "linux",
		"--static-host", target.Host, "--static-user", target.User, "--static-port", target.Port,
		"--static-work-root", workRoot, "--static-no-control-master", "--id", leaseID,
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		stopCommand := exec.CommandContext(cleanupCtx, binary, stopArgs...)
		stopCommand.Env = environment
		_ = stopCommand.Run()
	})

	unrelated, err := runSSHOutput(ctx, target, "setsid /bin/sh -c 'exec sleep 30' >/dev/null 2>&1 < /dev/null & printf '%s' $!")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runSSHQuiet(context.Background(), target, "kill "+unrelated+" 2>/dev/null || true") }()

	args := append(append([]string{}, baseArgs...), "--", "sh", "-lc", `printf 'CLI_CANCEL_STARTED\n'; sleep 30; printf 'CLI_CANCEL_BAD\n'`)
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = environment
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "CLI_CANCEL_STARTED" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("start line=%q err=%v stderr=%q", line, err, stderr.String())
	}

	ownerKey := workspaceOwnerKey(leaseID)
	childPath := `"$HOME/.crabbox/workspace-owners/` + ownerKey + `.child"`
	child, err := runSSHOutput(ctx, target, "cat "+childPath)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	metadata := strings.Split(strings.TrimSpace(child), "\n")
	if len(metadata) != 5 || metadata[0] != metadata[2] || metadata[0] != metadata[3] {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("non-dedicated CLI witness metadata=%q", child)
	}
	statePath := `"$HOME/.crabbox/workspace-owners/` + ownerKey + `.owner"`
	token, err := runSSHOutput(ctx, target, "sed -n '2p' "+statePath)
	if err != nil || len(strings.TrimSpace(token)) != 64 {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("read exact owner generation: %v", err)
	}
	request := func(action workspaceOwnerAction) workspaceOwnerRemoteRequest {
		return workspaceOwnerRemoteRequest{Action: action, Key: ownerKey, Token: strings.TrimSpace(token), TTL: time.Minute}
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		transport := sshWorkspaceOwnerTransport{target: target}
		_, _ = transport.Do(cleanupCtx, request(workspaceOwnerCancel))
		_, _ = transport.Do(cleanupCtx, request(workspaceOwnerRelease))
	})

	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	remaining, readErr := io.ReadAll(reader)
	waitErr := command.Wait()
	if readErr != nil {
		t.Fatal(readErr)
	}
	exit := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			t.Fatal(waitErr)
		}
		exit = exitErr.ExitCode()
	}
	if exit != 1 || strings.Contains(string(remaining), "CLI_CANCEL_BAD") || !strings.Contains(stderr.String(), "workspace owner released") {
		t.Fatalf("cancel exit=%d remaining=%q stderr=%q", exit, remaining, stderr.String())
	}
	waitForGroupQuiescence(t, metadata[2], metadata[3])
	if err := runSSHQuiet(ctx, target, "test ! -e "+childPath); err != nil {
		t.Fatalf("CLI cancellation retained child witness: %v", err)
	}
	if err := runSSHQuiet(ctx, target, "kill -0 "+unrelated); err != nil {
		t.Fatalf("unrelated remote process did not survive: %v", err)
	}

	nextArgs := append(append([]string{}, baseArgs...), "--", "printf", "CLI_NEXT_OK\\n")
	next := exec.CommandContext(ctx, binary, nextArgs...)
	next.Env = environment
	nextOutput, err := next.CombinedOutput()
	if err != nil || !strings.Contains(string(nextOutput), "CLI_NEXT_OK") {
		t.Fatalf("immediate reuse err=%v output=%q", err, nextOutput)
	}
	stopCommand := exec.CommandContext(ctx, binary, stopArgs...)
	stopCommand.Env = environment
	if output, err := stopCommand.CombinedOutput(); err != nil {
		t.Fatalf("static cleanup err=%v output=%q", err, output)
	}
}

func startWorkspaceOwnerRootlessSSHD(t *testing.T) (SSHTarget, func()) {
	t.Helper()
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		sshd = "/usr/sbin/sshd"
		if _, statErr := os.Stat(sshd); statErr != nil {
			t.Skip("sshd unavailable")
		}
	}
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen unavailable")
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hostKey, clientKey := filepath.Join(dir, "host"), filepath.Join(dir, "client")
	for _, key := range []string{hostKey, clientKey} {
		if out, err := exec.Command(sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v: %s", err, out)
		}
	}
	clientPublic, err := os.ReadFile(clientKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, clientPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	config := filepath.Join(dir, "sshd_config")
	contents := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nAddressFamily inet\nPidFile %s/sshd.pid\nHostKey %s\nAuthorizedKeysFile %s\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAllowUsers %s\nPermitTTY no\nPrintMotd no\nPrintLastLog no\nLogLevel ERROR\n", port, dir, hostKey, authorized, account.Username)
	if err := os.WriteFile(config, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	server := exec.Command(sshd, "-D", "-e", "-f", config)
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	stop := func() { _ = server.Process.Kill(); _ = server.Wait() }
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("sshd did not listen: %v", dialErr)
		}
		time.Sleep(25 * time.Millisecond)
	}
	hostPublic, err := os.ReadFile(hostKey + ".pub")
	if err != nil {
		stop()
		t.Fatal(err)
	}
	knownHosts := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte(fmt.Sprintf("[127.0.0.1]:%d %s\n", port, strings.TrimSpace(string(hostPublic)))), 0o600); err != nil {
		stop()
		t.Fatal(err)
	}
	return SSHTarget{User: account.Username, Host: "127.0.0.1", Port: strconv.Itoa(port), Key: clientKey, KnownHostsFile: knownHosts, TargetOS: targetLinux, NoControlMaster: true}, stop
}

func TestWorkspaceOwnerPOSIXCancelRejectsWrongOrExpiredGeneration(t *testing.T) {
	for _, test := range []struct {
		name       string
		request    string
		expire     bool
		wantOutput string
	}{
		{name: "wrong token", request: strings.Repeat("e", 64), wantOutput: "MISMATCH"},
		{name: "expired", request: strings.Repeat("d", 64), expire: true, wantOutput: "EXPIRED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			key, token := "cancel-generation", strings.Repeat("d", 64)
			request := func(action workspaceOwnerAction, requestToken string) workspaceOwnerRemoteRequest {
				return workspaceOwnerRemoteRequest{Action: action, Key: key, Token: requestToken, TTL: time.Minute}
			}
			if out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(request(workspaceOwnerAcquire, token))); err != nil || out != "ACQUIRED" {
				t.Fatalf("acquire out=%q err=%v", out, err)
			}
			state := filepath.Join(home, ".crabbox", "workspace-owners", key+".owner")
			if test.expire {
				if err := os.WriteFile(state, []byte("v1\n"+token+"\n1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out, err := runPOSIXWorkspaceOwnerScript(t, home, remoteWorkspaceOwnerPOSIX(request(workspaceOwnerCancel, test.request)))
			if err == nil || out != test.wantOutput {
				t.Fatalf("cancel out=%q err=%v", out, err)
			}
			if _, err := os.Stat(state); err != nil {
				t.Fatalf("rejected cancel removed owner state: %v", err)
			}
		})
	}
}
