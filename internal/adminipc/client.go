package adminipc

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/incident"
	"pulse-agent/internal/runbook"
	"pulse-agent/internal/target"
)

const (
	defaultRequestTimeout = 5 * time.Second

	// DefaultRequestTimeout bounds one local administrative IPC request when a
	// caller does not need a narrower deadline.
	DefaultRequestTimeout = defaultRequestTimeout
)

// ClientOptions configures an administrative IPC client. Clock and
// NewRequestID are explicit so callers can keep time and request correlation
// deterministic in controlled tests.
type ClientOptions struct {
	// RequestTimeout bounds one request and its response stream.
	RequestTimeout time.Duration
	// Clock returns the current time used to calculate connection deadlines.
	Clock func() time.Time
	// NewRequestID returns a unique, protocol-safe request identifier.
	NewRequestID func() (string, error)
}

// SystemClock returns the current wall-clock time for production assembly.
func SystemClock() time.Time {
	return time.Now()
}

// NewRequestID returns a cryptographically random, protocol-safe request ID.
func NewRequestID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "request-" + hex.EncodeToString(random[:]), nil
}

// NewAuditID returns a cryptographically random audit event ID.
func NewAuditID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "admin-" + hex.EncodeToString(random[:]), nil
}

// Client sends a single authenticated request to a daemon-owned local socket.
// Its zero value is not valid; construct it with NewClient.
type Client struct {
	requestTimeout time.Duration
	clock          func() time.Time
	newRequestID   func() (string, error)
}

// NewClient validates options and returns a client with explicit time and ID
// dependencies.
func NewClient(options ClientOptions) (*Client, error) {
	if options.RequestTimeout <= 0 || options.Clock == nil || options.NewRequestID == nil {
		return nil, ErrInvalidOptions
	}
	return &Client{
		requestTimeout: options.RequestTimeout,
		clock:          options.Clock,
		newRequestID:   options.NewRequestID,
	}, nil
}

// NewProductionClient returns a client assembled with the production clock
// and random request ID generator.
func NewProductionClient() (*Client, error) {
	return NewClient(ClientOptions{
		RequestTimeout: DefaultRequestTimeout,
		Clock:          SystemClock,
		NewRequestID:   NewRequestID,
	})
}

// Status requests the safe bounded daemon status without opening local state.
func (c *Client) Status(ctx context.Context, socketPath, reasonCode string) (Status, error) {
	response, _, connection, stopClose, err := c.request(ctx, socketPath, OperationStatus, reasonCode, nil, nil, nil, "")
	if stopClose != nil {
		defer stopClose()
	}
	if connection != nil {
		defer connection.Close()
	}
	if err != nil {
		return Status{}, err
	}
	if response.Status == nil || response.BackupSize != 0 || response.TargetResult != nil {
		return Status{}, ErrMalformedResponse
	}
	return *response.Status, nil
}

// Backup requests a consistent raw daemon-owned state snapshot and writes it to
// destination. The client never opens or reads the bbolt state file directly.
func (c *Client) Backup(ctx context.Context, socketPath, reasonCode string, destination io.Writer) error {
	if destination == nil {
		return ErrInvalidOptions
	}
	response, reader, connection, stopClose, err := c.request(ctx, socketPath, OperationBackup, reasonCode, nil, nil, nil, "")
	if stopClose != nil {
		defer stopClose()
	}
	if connection != nil {
		defer connection.Close()
	}
	if err != nil {
		return err
	}
	if response.Status != nil || response.BackupSize <= 0 || response.TargetResult != nil {
		return ErrMalformedResponse
	}
	written, err := io.CopyN(destination, reader, response.BackupSize)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrResponseTruncated
		}
		return err
	}
	if written != response.BackupSize {
		return ErrResponseTruncated
	}
	return nil
}

// Register submits a strict target document to the daemon. The client never
// opens local state, performs a target-store transaction, or writes audit data.
func (c *Client) Register(ctx context.Context, socketPath, reasonCode string, submitted contract.ServiceTarget) (target.RegistrationResult, error) {
	response, _, connection, stopClose, err := c.request(ctx, socketPath, OperationTargetRegister, reasonCode, &submitted, nil, nil, "")
	if stopClose != nil {
		defer stopClose()
	}
	if connection != nil {
		defer connection.Close()
	}
	if err != nil {
		return target.RegistrationResult{}, err
	}
	if response.Status != nil || response.BackupSize != 0 || response.TargetResult == nil {
		return target.RegistrationResult{}, ErrMalformedResponse
	}
	return *response.TargetResult, nil
}

// RegisterRunbook submits a previously validated typed runbook through the
// daemon-owned local IPC boundary.
func (c *Client) RegisterRunbook(ctx context.Context, socketPath, reasonCode string, submitted contract.Runbook) (runbook.RegistrationResult, error) {
	response, _, connection, stopClose, err := c.request(ctx, socketPath, OperationRunbookRegister, reasonCode, nil, &submitted, nil, "")
	if stopClose != nil {
		defer stopClose()
	}
	if connection != nil {
		defer connection.Close()
	}
	if err != nil {
		return runbook.RegistrationResult{}, err
	}
	if response.Status != nil || response.BackupSize != 0 || response.TargetResult != nil || response.RunbookResult == nil {
		return runbook.RegistrationResult{}, ErrMalformedResponse
	}
	return *response.RunbookResult, nil
}

func (c *Client) ListIncidents(ctx context.Context, socketPath, reasonCode string, filter incident.Filter) (incident.Page, error) {
	response, _, connection, stopClose, err := c.request(ctx, socketPath, OperationIncidentList, reasonCode, nil, nil, &filter, "")
	if stopClose != nil {
		defer stopClose()
	}
	if connection != nil {
		defer connection.Close()
	}
	if err != nil {
		return incident.Page{}, err
	}
	if response.IncidentPage == nil {
		return incident.Page{}, ErrMalformedResponse
	}
	return *response.IncidentPage, nil
}

func (c *Client) ShowIncident(ctx context.Context, socketPath, reasonCode, id string) (contract.Incident, error) {
	response, _, connection, stopClose, err := c.request(ctx, socketPath, OperationIncidentShow, reasonCode, nil, nil, nil, id)
	if stopClose != nil {
		defer stopClose()
	}
	if connection != nil {
		defer connection.Close()
	}
	if errors.Is(err, ErrRequestRejected) && response.ErrorCode == errorIncidentNotFound {
		return contract.Incident{}, ErrIncidentNotFound
	}
	if err != nil {
		return contract.Incident{}, err
	}
	if response.Incident == nil {
		return contract.Incident{}, ErrMalformedResponse
	}
	return *response.Incident, nil
}

func (c *Client) request(ctx context.Context, socketPath string, operation Operation, reasonCode string, submitted *contract.ServiceTarget, submittedRunbook *contract.Runbook, filter *incident.Filter, incidentID string) (response, *bufio.Reader, *net.UnixConn, func() bool, error) {
	if ctx == nil || c == nil || c.requestTimeout <= 0 || c.clock == nil || c.newRequestID == nil || !validOperation(operation) || !validReasonCode(reasonCode) {
		return response{}, nil, nil, nil, ErrInvalidOptions
	}
	requestID, err := c.newRequestID()
	if err != nil {
		return response{}, nil, nil, nil, ErrDaemonUnavailable
	}
	connection, err := c.connect(ctx, socketPath)
	if err != nil {
		return response{}, nil, nil, nil, err
	}
	stopClose := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})

	request := Request{
		SchemaVersion:  SchemaVersion,
		RequestID:      requestID,
		Operation:      operation,
		ReasonCode:     reasonCode,
		Target:         submitted,
		Runbook:        submittedRunbook,
		IncidentFilter: filter,
		IncidentID:     incidentID,
	}
	if err := writeMessage(connection, request); err != nil {
		stopClose()
		_ = connection.Close()
		return response{}, nil, nil, nil, transportError(ctx)
	}
	reader := bufioReader(connection)
	document, err := readMessage(reader)
	if err != nil {
		stopClose()
		_ = connection.Close()
		return response{}, nil, nil, nil, transportError(ctx)
	}
	decoded, err := decodeResponse(document)
	if err != nil || (decoded.RequestID != requestID && !(decoded.Result == resultFailure && decoded.RequestID == "")) {
		stopClose()
		_ = connection.Close()
		return response{}, nil, nil, nil, ErrMalformedResponse
	}
	if decoded.Result == resultFailure {
		stopClose()
		_ = connection.Close()
		return decoded, nil, nil, nil, ErrRequestRejected
	}

	return decoded, reader, connection, stopClose, nil
}

func (c *Client) connect(ctx context.Context, socketPath string) (*net.UnixConn, error) {
	before, err := inspectClientSocket(socketPath)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: c.requestTimeout}
	connected, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, transportError(ctx)
	}
	connection, ok := connected.(*net.UnixConn)
	if !ok {
		_ = connected.Close()
		return nil, ErrDaemonUnavailable
	}
	after, err := inspectClientSocket(socketPath)
	if err != nil || !os.SameFile(before, after) {
		_ = connection.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrSocketReplaced
	}
	deadline := c.clock().Add(c.requestTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return nil, ErrDaemonUnavailable
	}
	return connection, nil
}

func transportError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrDaemonUnavailable
}
