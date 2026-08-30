package backup

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// CopyResult reports what CopyTree copied.
type CopyResult struct {
	Files int
	Bytes int64
}

// CopyTree copies every regular file under src into dst, preserving the
// relative path and file mode, creating directories (0700) as needed. A
// missing src is not an error — it reports a zero CopyResult, since "the DKIM
// directory does not exist yet" is a valid (if unusual) state to back up.
//
// Symlinks and other non-regular entries are skipped, never followed: a
// crafted symlink under a key or config directory must not let a copy read or
// overwrite a path outside src/dst.
func CopyTree(src, dst string) (CopyResult, error) {
	var res CopyResult
	info, err := os.Lstat(src)
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, fmt.Errorf("backup: stat %s: %w", src, err)
	}
	if !info.IsDir() {
		return res, fmt.Errorf("backup: %s is not a directory", src)
	}

	err = filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o700)
		case d.Type()&os.ModeSymlink != 0:
			return nil // never follow symlinks into or out of the tree
		case !d.Type().IsRegular():
			return nil // sockets, devices, etc.: not meaningful to back up
		default:
			n, cerr := CopyFile(path, target)
			if cerr != nil {
				return cerr
			}
			res.Files++
			res.Bytes += n
			return nil
		}
	})
	if err != nil {
		return res, fmt.Errorf("backup: copy %s: %w", src, err)
	}
	return res, nil
}

// CopyFile copies one regular file from src to dst, preserving src's file
// mode and creating dst's parent directory (0700) if needed. It returns the
// number of bytes copied.
func CopyFile(src, dst string) (int64, error) {
	info, err := os.Stat(src)
	if err != nil {
		return 0, fmt.Errorf("backup: stat %s: %w", src, err)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("backup: %s is not a regular file", src)
	}

	// src/dst are constructed by callers from an operator-configured directory
	// (config path, DKIM dir, bundle dir) walked or joined with fixed/validated
	// components — not from unsanitised network or request input.
	in, err := os.Open(src) // #nosec G304 -- path from an operator-configured tree, see callers
	if err != nil {
		return 0, err
	}
	defer func() { _ = in.Close() }()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return 0, err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm()) // #nosec G304 -- destination under an operator-configured bundle/target directory
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return n, copyErr
	}
	return n, closeErr
}

// DirSize returns the total size in bytes of every regular file under dir,
// recursively. A missing dir reports zero, not an error.
func DirSize(dir string) (int64, error) {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type().IsRegular() {
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}
