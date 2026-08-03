//go:build windows

package tail

import (
	"os"
	"syscall"
)

// openShared opens the log in a way that still lets another process rename or
// delete it underneath us.
//
// Go's os.Open does not pass FILE_SHARE_DELETE on Windows, so simply holding the
// file open blocks rotation: logrotate fails, eve.json grows without limit, and
// we have broken the thing we were only supposed to be watching. Reading a log
// must never be able to affect the writer, so the handle is opened by hand with
// all three sharing modes.
func openShared(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(
		p,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
