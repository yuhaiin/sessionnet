//go:build !linux

package sessionnet

import "errors"

// CgroupManager is unavailable on non-Linux platforms.
type CgroupManager struct{}

func NewCgroupManager(string) (*CgroupManager, error) {
	return nil, ErrUnsupported
}

func (*CgroupManager) Close() error {
	return errors.ErrUnsupported
}
