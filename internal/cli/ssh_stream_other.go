//go:build !windows

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
)

func runCommandWithPlatformStreams(cmd *exec.Cmd, stdout, stderr io.Writer) error {
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func runOwnedSSHCommandWithPlatformStreams(ctx context.Context, handle *pondMeshExecHandle, stdout, stderr io.Writer) error {
	type streamCopy struct {
		read  *os.File
		write *os.File
		done  chan error
	}
	startCopy := func(dst io.Writer) (*streamCopy, error) {
		read, write, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		copy := &streamCopy{read: read, write: write, done: make(chan error, 1)}
		go func() {
			_, copyErr := io.Copy(dst, read)
			copy.done <- errors.Join(copyErr, read.Close())
		}()
		return copy, nil
	}
	var copies []*streamCopy
	closeCopies := func() {
		for _, copy := range copies {
			_ = copy.write.Close()
		}
	}
	closeCopyReaders := func() {
		for _, copy := range copies {
			_ = copy.read.Close()
		}
	}
	collectCopies := func() error {
		var errs []error
		for index, copy := range copies {
			select {
			case err := <-copy.done:
				errs = append(errs, err)
				continue
			default:
			}
			select {
			case err := <-copy.done:
				errs = append(errs, err)
			case <-ctx.Done():
				// The owned process group has already been reaped before collection
				// begins. Stop future pipe reads, but do not wait for a Write already
				// blocked inside an arbitrary caller-owned writer; that goroutine can
				// only finish when the writer returns.
				closeCopyReaders()
				errs = append(errs, context.Cause(ctx))
				for _, pending := range copies[index:] {
					select {
					case err := <-pending.done:
						errs = append(errs, err)
					default:
					}
				}
				return errors.Join(errs...)
			}
		}
		return errors.Join(errs...)
	}
	if stdout != nil {
		copy, err := startCopy(stdout)
		if err != nil {
			return err
		}
		copies = append(copies, copy)
		handle.cmd.Stdout = copy.write
	}
	if stderr != nil {
		if stdout != nil && sameCommandStreamWriter(stdout, stderr) {
			handle.cmd.Stderr = copies[0].write
		} else {
			copy, err := startCopy(stderr)
			if err != nil {
				closeCopies()
				_ = collectCopies()
				return err
			}
			copies = append(copies, copy)
			handle.cmd.Stderr = copy.write
		}
	}
	if err := handle.Start(); err != nil {
		closeCopies()
		return errors.Join(err, collectCopies())
	}
	closeCopies()
	waitErr := waitOwnedSSHTransportCommand(ctx, handle)
	return errors.Join(waitErr, collectCopies())
}
