//go:build !linux

package adminipc

import "net"

func platformPeerCredentials(*net.UnixConn) (Actor, error) {
	return Actor{}, ErrPeerCredentialsUnavailable
}
