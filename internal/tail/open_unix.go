//go:build !windows

package tail

import "os"

// openShared opens the log for reading. On Unix a rename or unlink never asks
// the reader's permission, so there is nothing special to arrange.
func openShared(path string) (*os.File, error) { return os.Open(path) }
