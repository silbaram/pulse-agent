package adminipc

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

const socketMode os.FileMode = 0o660

func validateSocketPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalidOptions
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() {
		return ErrInsecureSocket
	}
	return nil
}

func inspectClientSocket(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrDaemonUnavailable
	}
	if err != nil || !isSafeSocket(info) {
		return nil, ErrInsecureSocket
	}
	return info, nil
}

func verifyDaemonSocket(info os.FileInfo, ownerUID, ownerGID uint32) error {
	if !isSafeSocket(info) {
		return ErrInsecureSocket
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Gid != ownerGID {
		return ErrInsecureSocket
	}
	return nil
}

func isSafeSocket(info os.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return false
	}
	return info.Mode().Perm()&^socketMode == 0
}

func currentSocket(path string, expected os.FileInfo, ownerUID, ownerGID uint32) bool {
	if expected == nil {
		return false
	}
	actual, err := os.Lstat(path)
	if err != nil || !os.SameFile(expected, actual) {
		return false
	}
	return verifyDaemonSocket(actual, ownerUID, ownerGID) == nil
}

func removeOwnedSocket(path string, expected os.FileInfo, ownerUID, ownerGID uint32) error {
	if !currentSocket(path, expected, ownerUID, ownerGID) {
		return nil
	}
	return os.Remove(path)
}

func listenSocket(path string, ownerUID, ownerGID uint32) (*net.UnixListener, os.FileInfo, error) {
	if err := validateSocketPath(path); err != nil {
		return nil, nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, nil, ErrSocketPathExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, ErrInsecureSocket
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, ErrDaemonUnavailable
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, socketMode); err != nil {
		return nil, nil, errors.Join(ErrInsecureSocket, listener.Close())
	}
	if err := os.Chown(path, int(ownerUID), int(ownerGID)); err != nil {
		return nil, nil, errors.Join(ErrInsecureSocket, listener.Close())
	}
	info, err := os.Lstat(path)
	if err != nil || verifyDaemonSocket(info, ownerUID, ownerGID) != nil {
		return nil, nil, errors.Join(ErrInsecureSocket, listener.Close())
	}
	return listener, info, nil
}
