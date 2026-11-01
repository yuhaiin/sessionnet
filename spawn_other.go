//go:build !linux

package sessionnet

import (
	"context"
)

// Process is unsupported on non-Linux platforms.
type Process struct{}

func (*Session) Spawn(context.Context, Config) (*Process, error) { return nil, ErrUnsupported }
func (*Process) PID() int                                        { return 0 }
func (*Process) Done() <-chan struct{}                           { return nil }
func (*Process) Wait() error                                     { return ErrUnsupported }
func (*Process) Close() error                                    { return nil }
