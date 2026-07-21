//go:build linux

package adminipc

import (
	"net"

	"golang.org/x/sys/unix"
)

func platformPeerCredentials(connection *net.UnixConn) (Actor, error) {
	rawConnection, err := connection.SyscallConn()
	if err != nil {
		return Actor{}, ErrPeerCredentialsUnavailable
	}

	var credentials *unix.Ucred
	controlErr := rawConnection.Control(func(fileDescriptor uintptr) {
		credentials, err = unix.GetsockoptUcred(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if controlErr != nil || err != nil || credentials == nil {
		return Actor{}, ErrPeerCredentialsUnavailable
	}
	return Actor{UID: credentials.Uid, GID: credentials.Gid}, nil
}
