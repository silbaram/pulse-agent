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
)

// Client sends a single authenticated request to a daemon-owned local socket.
// Its zero value is not valid; construct it with NewClient.
type Client struct {
	requestTimeout time.Duration
}

// NewClient returns a client using the default bounded request timeout.
func NewClient() *Client {
	return &Client{requestTimeout: defaultRequestTimeout}
}

// Status requests the safe bounded daemon status without opening local state.
func (c *Client) Status(ctx context.Context, socketPath, reasonCode string) (Status, error) {
	response, _, connection, stopClose, err := c.request(ctx, socketPath, OperationStatus, reasonCode)
	if stopClose != nil {
		defer stopClose()
	}
	if connection != nil {
		defer connection.Close()
	}
	if err != nil {
		return Status{}, err
	}
	if response.Status == nil || response.BackupSize != 0 {
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
	response, reader, connection, stopClose, err := c.request(ctx, socketPath, OperationBackup, reasonCode)
	if stopClose != nil {
		defer stopClose()
	}
	if connection != nil {
		defer connection.Close()
	}
	if err != nil {
		return err
	}
	if response.Status != nil || response.BackupSize <= 0 {
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

func (c *Client) request(ctx context.Context, socketPath string, operation Operation, reasonCode string) (response, *bufio.Reader, *net.UnixConn, func() bool, error) {
	if ctx == nil || c == nil || c.requestTimeout <= 0 || !validOperation(operation) || !validReasonCode(reasonCode) {
		return response{}, nil, nil, nil, ErrInvalidOptions
	}
	requestID, err := newRequestID()
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
		SchemaVersion: SchemaVersion,
		RequestID:     requestID,
		Operation:     operation,
		ReasonCode:    reasonCode,
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
		return response{}, nil, nil, nil, ErrRequestRejected
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
	deadline := time.Now().Add(c.requestTimeout)
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

func newRequestID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "request-" + hex.EncodeToString(random[:]), nil
}
