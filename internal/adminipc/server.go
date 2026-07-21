package adminipc

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"pulse-agent/internal/audit"
	"pulse-agent/internal/contract"
	"pulse-agent/internal/store"
	"pulse-agent/internal/target"
)

const (
	defaultRequestTimeout = 5 * time.Second

	auditAggregateType       = "admin_request"
	auditActionRequest       = "admin.request"
	auditActionStatus        = "admin.status"
	auditActionBackup        = "admin.backup"
	auditResultAccepted      = "accepted"
	auditResultRejected      = "rejected"
	auditReasonMalformed     = "malformed_request"
	auditReasonUnauthorized  = "peer_unauthorized"
	errorAuthentication      = "authentication_failed"
	errorPermissionDenied    = "permission_denied"
	errorMalformedRequest    = "malformed_request"
	errorTargetRejected      = "target_rejected"
	auditReasonUnsupported   = "unsupported_operation"
	statusCapabilityAdminIPC = "admin_ipc"
	statusUnsupportedHost    = "host_power_os_network_outage"
)

// PeerCredentials obtains an immutable operating-system identity for one Unix
// socket peer. A nil or failing result is rejected before routing the request.
type PeerCredentials func(*net.UnixConn) (Actor, error)

// Options configures one daemon-owned administrative IPC server.
type Options struct {
	// SocketPath is the absolute, clean Unix socket path owned by the daemon.
	SocketPath string
	// AllowedUIDs contains every UID authorized to make administrative requests.
	AllowedUIDs []uint32
	// AllowedGIDs contains every GID authorized to make administrative requests.
	AllowedGIDs []uint32
	// State is the daemon-owned store used for audit records and backups.
	State *store.Store
	// Targets routes target registrations through one daemon-owned registry.
	// It may be nil when a server exposes only the earlier status and backup API.
	Targets *target.Registry
	// RequestTimeout bounds each authenticated request and backup stream. Zero
	// uses the safe default timeout.
	RequestTimeout time.Duration
	// PeerCredentials overrides the operating-system peer lookup for controlled
	// tests. Production callers should leave it nil.
	PeerCredentials PeerCredentials
}

// Server owns one protected Unix socket and routes authenticated administrative
// requests. Its zero value is not valid; construct it with NewServer.
type Server struct {
	socketPath      string
	ownerUID        uint32
	ownerGID        uint32
	allowedUIDs     map[uint32]struct{}
	allowedGIDs     map[uint32]struct{}
	state           *store.Store
	targets         *target.Registry
	requestTimeout  time.Duration
	peerCredentials PeerCredentials

	mu          sync.Mutex
	started     bool
	closed      bool
	closeDone   chan struct{}
	closeErr    error
	listener    *net.UnixListener
	socketInfo  os.FileInfo
	connections map[*net.UnixConn]struct{}
	workers     sync.WaitGroup
}

// NewServer validates options and returns a server that has not bound its
// socket yet. Both UID and GID allowlists must match for a peer to be allowed.
func NewServer(options Options) (*Server, error) {
	if err := validateSocketPath(options.SocketPath); err != nil || options.State == nil {
		return nil, ErrInvalidOptions
	}
	allowedUIDs, ok := identitySet(options.AllowedUIDs)
	if !ok {
		return nil, ErrInvalidOptions
	}
	allowedGIDs, ok := identitySet(options.AllowedGIDs)
	if !ok {
		return nil, ErrInvalidOptions
	}
	if os.Getuid() < 0 || os.Getgid() < 0 {
		return nil, ErrInvalidOptions
	}

	timeout := options.RequestTimeout
	if timeout == 0 {
		timeout = defaultRequestTimeout
	}
	if timeout < 0 {
		return nil, ErrInvalidOptions
	}
	peerCredentials := options.PeerCredentials
	if peerCredentials == nil {
		peerCredentials = platformPeerCredentials
	}

	return &Server{
		socketPath:      options.SocketPath,
		ownerUID:        uint32(os.Getuid()),
		ownerGID:        uint32(os.Getgid()),
		allowedUIDs:     allowedUIDs,
		allowedGIDs:     allowedGIDs,
		state:           options.State,
		targets:         options.Targets,
		requestTimeout:  timeout,
		peerCredentials: peerCredentials,
		connections:     make(map[*net.UnixConn]struct{}),
		closeDone:       make(chan struct{}),
	}, nil
}

// Serve binds the protected socket, accepts concurrent authenticated requests,
// and closes both the listener and active connections when ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidOptions
	}
	if err := s.begin(); err != nil {
		return err
	}

	stopClose := context.AfterFunc(ctx, func() {
		_ = s.Close()
	})
	defer stopClose()

	listener, socketInfo, err := listenSocket(s.socketPath, s.ownerUID, s.ownerGID)
	if err != nil {
		_ = s.Close()
		return err
	}
	if !s.installListener(listener, socketInfo) {
		_ = listener.Close()
		_ = removeOwnedSocket(s.socketPath, socketInfo, s.ownerUID, s.ownerGID)
		return nil
	}

	var serveErr error
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if s.isClosed() || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			serveErr = ErrDaemonUnavailable
			break
		}
		if !s.socketIsCurrent() {
			_ = connection.Close()
			serveErr = ErrSocketReplaced
			break
		}
		if !s.trackConnection(connection) {
			_ = connection.Close()
			break
		}
		go s.serveConnection(connection)
	}

	_ = s.Close()
	s.workers.Wait()
	return serveErr
}

// Close stops accepting work, cancels active connections, and removes the
// socket only when the current path still names the daemon-created socket.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		closeDone := s.closeDone
		s.mu.Unlock()
		<-closeDone
		return s.closeErr
	}
	s.closed = true
	listener := s.listener
	s.listener = nil
	socketInfo := s.socketInfo
	connections := make([]*net.UnixConn, 0, len(s.connections))
	for connection := range s.connections {
		connections = append(connections, connection)
	}
	s.mu.Unlock()

	var closeErr error
	if listener != nil {
		closeErr = listener.Close()
	}
	for _, connection := range connections {
		if err := connection.Close(); closeErr == nil && err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = err
		}
	}
	if err := removeOwnedSocket(s.socketPath, socketInfo, s.ownerUID, s.ownerGID); closeErr == nil && err != nil {
		closeErr = err
	}
	s.mu.Lock()
	s.closeErr = closeErr
	close(s.closeDone)
	s.mu.Unlock()
	return closeErr
}

func (s *Server) begin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return ErrAlreadyServing
	}
	s.started = true
	return nil
}

func (s *Server) installListener(listener *net.UnixListener, socketInfo os.FileInfo) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.listener = listener
	s.socketInfo = socketInfo
	return true
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) socketIsCurrent() bool {
	s.mu.Lock()
	socketInfo := s.socketInfo
	s.mu.Unlock()
	return currentSocket(s.socketPath, socketInfo, s.ownerUID, s.ownerGID)
}

func (s *Server) trackConnection(connection *net.UnixConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.connections[connection] = struct{}{}
	s.workers.Add(1)
	return true
}

func (s *Server) serveConnection(connection *net.UnixConn) {
	defer s.workers.Done()
	defer func() {
		s.mu.Lock()
		delete(s.connections, connection)
		s.mu.Unlock()
		_ = connection.Close()
	}()

	if !s.socketIsCurrent() {
		return
	}
	if err := connection.SetDeadline(time.Now().Add(s.requestTimeout)); err != nil {
		return
	}

	actor, err := s.peerCredentials(connection)
	if err != nil {
		_ = writeMessage(connection, failureResponse("", errorAuthentication))
		return
	}
	if !s.authorized(actor) {
		if s.appendAudit(actor, "", auditActionRequest, auditResultRejected, auditReasonUnauthorized) != nil {
			return
		}
		_ = writeMessage(connection, failureResponse("", errorPermissionDenied))
		return
	}

	reader := bufioReader(connection)
	document, err := readMessage(reader)
	if err != nil {
		if s.appendAudit(actor, "", auditActionRequest, auditResultRejected, auditReasonMalformed) == nil {
			_ = writeMessage(connection, failureResponse("", errorMalformedRequest))
		}
		return
	}
	request, err := decodeRequest(document)
	if err != nil {
		if s.appendAudit(actor, "", auditActionRequest, auditResultRejected, auditReasonMalformed) == nil {
			_ = writeMessage(connection, failureResponse("", errorMalformedRequest))
		}
		return
	}

	s.route(connection, actor, request)
}

func (s *Server) route(connection *net.UnixConn, actor Actor, request Request) {
	switch request.Operation {
	case OperationStatus:
		if s.appendAudit(actor, request.RequestID, auditActionStatus, auditResultAccepted, request.ReasonCode) != nil {
			return
		}
		_ = writeMessage(connection, response{
			SchemaVersion: SchemaVersion,
			RequestID:     request.RequestID,
			Result:        resultSuccess,
			Status: &Status{
				SchemaVersion: SchemaVersion,
				State:         StatusRunning,
				Capabilities:  []string{statusCapabilityAdminIPC},
				Unsupported:   []string{statusUnsupportedHost},
			},
		})
	case OperationBackup:
		if s.appendAudit(actor, request.RequestID, auditActionBackup, auditResultAccepted, request.ReasonCode) != nil {
			return
		}
		_ = s.state.BackupWithSize(connection, func(size int64) error {
			return writeMessage(connection, response{
				SchemaVersion: SchemaVersion,
				RequestID:     request.RequestID,
				Result:        resultSuccess,
				BackupSize:    size,
			})
		})
	case OperationTargetRegister:
		if s.targets == nil || request.Target == nil {
			if s.appendAudit(actor, request.RequestID, auditActionRequest, auditResultRejected, auditReasonUnsupported) == nil {
				if err := writeMessage(connection, failureResponse(request.RequestID, errorTargetRejected)); err != nil {
					return
				}
			}
			return
		}
		snapshot, err := s.targets.Register(target.Registration{
			Target:        *request.Target,
			ActorIdentity: actor.Identity(),
			RequestID:     request.RequestID,
			ReasonCode:    request.ReasonCode,
		})
		if err != nil {
			if writeErr := writeMessage(connection, failureResponse(request.RequestID, errorTargetRejected)); writeErr != nil {
				return
			}
			return
		}
		result := target.RegistrationResult{
			SchemaVersion: SchemaVersion,
			Version:       snapshot.Version,
			TargetID:      request.Target.TargetID,
		}
		if err := writeMessage(connection, response{
			SchemaVersion: SchemaVersion,
			RequestID:     request.RequestID,
			Result:        resultSuccess,
			TargetResult:  &result,
		}); err != nil {
			return
		}
	}
}

func (s *Server) authorized(actor Actor) bool {
	_, uidAllowed := s.allowedUIDs[actor.UID]
	_, gidAllowed := s.allowedGIDs[actor.GID]
	return uidAllowed && gidAllowed
}

func (s *Server) appendAudit(actor Actor, requestID, action, outcome, reason string) error {
	eventID, err := newAuditID()
	if err != nil {
		return err
	}
	return s.state.Update(func(transaction *store.Tx) error {
		_, err := audit.Append(transaction, contract.AuditEvent{
			SchemaVersion: SchemaVersion,
			EventID:       eventID,
			AggregateType: auditAggregateType,
			AggregateID:   auditAggregateID(requestID),
			ActorIdentity: actor.Identity(),
			Action:        action,
			Result:        outcome,
			ReasonCode:    reason,
			OccurredAt:    time.Now(),
		}, nil)
		return err
	})
}

func failureResponse(requestID, code string) response {
	return response{
		SchemaVersion: SchemaVersion,
		RequestID:     requestID,
		Result:        resultFailure,
		ErrorCode:     code,
	}
}

func identitySet(identities []uint32) (map[uint32]struct{}, bool) {
	if len(identities) == 0 {
		return nil, false
	}
	set := make(map[uint32]struct{}, len(identities))
	for _, identity := range identities {
		if _, duplicate := set[identity]; duplicate {
			return nil, false
		}
		set[identity] = struct{}{}
	}
	return set, true
}

func newAuditID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "admin-" + hex.EncodeToString(random[:]), nil
}

func auditAggregateID(requestID string) string {
	if requestID == "" {
		return "request-unknown"
	}
	return "request-" + requestID
}

func bufioReader(connection *net.UnixConn) *bufio.Reader {
	return bufio.NewReaderSize(connection, maxWireLineBytes)
}
