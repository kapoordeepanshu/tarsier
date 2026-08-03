// Package tail follows a log file that something else is rotating underneath it.
//
// Suricata writes eve.json continuously and logrotate, or Suricata itself, moves
// it out from under any reader on a schedule. Getting that wrong is the classic
// way a log shipper quietly loses data, so the two mechanisms are handled
// separately and explicitly:
//
//   - rename-and-create, where the file we hold is renamed and a new one appears
//     at the same path. The handle stays valid and still has unread bytes in it,
//     so we drain it to EOF before switching. Watching the path instead of the
//     handle loses the tail of every rotation.
//
//   - copytruncate, where the file is copied and then truncated in place. The
//     handle and the identity are unchanged; the only symptom is that the file
//     is suddenly smaller than our position.
//
// Assuming only the first is how tailers lose a chunk of every rotation on the
// distributions that default to the second.
package tail

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// maxLine caps how much a single unterminated line may buffer. A log file being
// written by another process always has a partial last line, which is normal and
// held until its newline arrives — but a file that never produces one is
// corrupt, and buffering it forever would be a slow way to run out of memory.
const maxLine = 8 << 20

// ErrLineTooLong is returned when a single line exceeds maxLine. The partial
// data is discarded and following continues from the next newline.
var ErrLineTooLong = errors.New("tail: line exceeds maximum length")

// Follower reads new lines from a file as they are written.
//
// It is not safe for concurrent use, and it never blocks: Poll returns what is
// available right now, so the caller owns the timing.
type Follower struct {
	path string

	file    *os.File
	off     int64  // where we are in the open file
	partial []byte // bytes after the last newline, waiting for the rest of the line

	// Rotations and Truncations count what happened while following. Worth
	// surfacing rather than hiding: a sensor that rotated forty times in an hour
	// is telling you something about its disk.
	Rotations   int
	Truncations int
}

// New returns a Follower for path. The file does not have to exist yet — a
// sensor is often configured before Suricata has written anything — and Poll
// will pick it up when it appears.
//
// Following starts at the beginning of the file, not the end. The current
// eve.json is at most one rotation period old, and reading it costs a second;
// skipping it would silently lose everything since the last rotation.
func New(path string) *Follower {
	return &Follower{path: path}
}

// Close releases the open handle. A Follower may be reused after Close.
func (f *Follower) Close() error {
	if f.file == nil {
		return nil
	}
	err := f.file.Close()
	f.file = nil
	return err
}

// Poll reads everything available right now, calling fn once per complete line.
// The slice passed to fn is only valid until fn returns.
//
// A partial trailing line is held until the writer finishes it. Rotation and
// truncation are handled transparently; the caller sees an unbroken sequence of
// lines across both.
func (f *Follower) Poll(fn func(line []byte)) (int, error) {
	lines := 0
	// Several rotations can land between two polls on a busy sensor. The bound
	// stops a pathological loop without pretending one rotation per poll is
	// enough.
	for range 16 {
		if f.file == nil {
			opened, err := f.open()
			if err != nil {
				return lines, err
			}
			if !opened {
				return lines, nil // nothing at that path yet
			}
		}

		n, readErr := f.drain(fn)
		lines += n

		again, err := f.recheck()
		if err != nil {
			return lines, err
		}
		if readErr != nil {
			return lines, readErr
		}
		if !again {
			return lines, nil
		}
	}
	return lines, nil
}

// open attaches to the file, reporting whether it was there.
func (f *Follower) open() (bool, error) {
	file, err := openShared(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	f.file = file
	f.off = 0
	f.partial = f.partial[:0]
	return true, nil
}

// drain reads to EOF, emitting every complete line.
func (f *Follower) drain(fn func(line []byte)) (int, error) {
	buf := make([]byte, 64<<10)
	lines := 0
	for {
		n, err := f.file.Read(buf)
		if n > 0 {
			f.off += int64(n)
			f.partial = append(f.partial, buf[:n]...)

			rest := f.partial
			for {
				i := bytes.IndexByte(rest, '\n')
				if i < 0 {
					break
				}
				line := rest[:i]
				// Tolerate CRLF, which is what a log copied via a Windows share
				// comes back as.
				if len(line) > 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
				fn(line)
				lines++
				rest = rest[i+1:]
			}
			// Keep only the unterminated remainder, copied down rather than
			// resliced so the backing array does not grow without bound.
			f.partial = append(f.partial[:0], rest...)

			if len(f.partial) > maxLine {
				f.partial = f.partial[:0]
				return lines, ErrLineTooLong
			}
		}
		if errors.Is(err, io.EOF) {
			return lines, nil
		}
		if err != nil {
			return lines, err
		}
	}
}

// recheck looks for rotation or truncation, and reports whether there is more to
// read. It runs only after drain has taken the current handle to EOF, which is
// what makes the rename case lossless.
func (f *Follower) recheck() (bool, error) {
	onDisk, err := os.Stat(f.path)
	if errors.Is(err, os.ErrNotExist) {
		// Rotated away and no replacement yet. Let go of the handle; the next
		// Poll picks the new file up when it appears.
		f.Rotations++
		return false, f.Close()
	}
	if err != nil {
		return false, err
	}

	open, err := f.file.Stat()
	if err != nil {
		return false, err
	}

	// Renamed out from under us: the path now names a different file. We are
	// already at EOF on the old one, so nothing is lost by letting it go.
	if !os.SameFile(onDisk, open) {
		f.Rotations++
		if err := f.Close(); err != nil {
			return false, err
		}
		return true, nil
	}

	// Same file, but smaller than our position: copied elsewhere and truncated
	// in place. Everything from here is new.
	if onDisk.Size() < f.off {
		if _, err := f.file.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
		f.off = 0
		f.partial = f.partial[:0]
		f.Truncations++
		return true, nil
	}

	return false, nil
}

// Position reports where the follower has read to, and a fingerprint of the file
// it was reading, so a caller persisting its own state can resume there.
//
// The fingerprint is the head of the file rather than its inode. Inodes are not
// portable, are not stable across a restore, and cannot be written to a file and
// believed later — whereas a log whose first bytes still match is, for this
// purpose, the same log.
func (f *Follower) Position() (offset int64, sig string) {
	if f.file == nil || f.off <= 0 {
		return 0, ""
	}
	return f.off, fingerprint(f.file, f.off)
}

// Resume continues from a position recorded earlier, and reports whether it
// could.
//
// It refuses when the file's head no longer matches, or when the file is now
// shorter than the offset. Both mean the log was rotated or truncated while we
// were away, and starting from the beginning is right — re-reading a little is
// recoverable, whereas silently skipping past unread events is not.
func (f *Follower) Resume(offset int64, sig string) (bool, error) {
	if offset <= 0 || sig == "" {
		return false, nil
	}
	if f.file == nil {
		opened, err := f.open()
		if err != nil || !opened {
			return false, err
		}
	}
	info, err := f.file.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() < offset {
		return false, nil
	}
	if fingerprint(f.file, offset) != sig {
		return false, nil
	}
	if _, err := f.file.Seek(offset, io.SeekStart); err != nil {
		return false, err
	}
	f.off = offset
	f.partial = f.partial[:0]
	return true, nil
}

// fingerprint hashes the head of the file, over a length derived from the
// offset so that both sides of a resume measure the same bytes.
//
// Hashing "the first 256 bytes, or the whole file if it is smaller" was the
// first attempt and was quietly wrong: a young log changes its own fingerprint
// every time it grows, so a resume would always be refused and every restart
// would re-read from the beginning.
func fingerprint(file *os.File, offset int64) string {
	n := offset
	if n > 256 {
		n = 256
	}
	head := make([]byte, n)
	read, err := file.ReadAt(head, 0)
	if int64(read) < n && err != nil {
		return ""
	}
	sum := sha256.Sum256(head[:read])
	return hex.EncodeToString(sum[:8])
}
