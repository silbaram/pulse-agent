// Package adminipc provides the daemon-owned local administrative IPC boundary.
package adminipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/incident"
	"pulse-agent/internal/runbook"
	"pulse-agent/internal/target"
)

const (
	// SchemaVersion is the version accepted by the administrative IPC protocol.
	SchemaVersion = contract.SchemaVersionV1
	// DefaultReasonCode identifies an operator request without introducing a
	// free-form audit value.
	DefaultReasonCode = "operator_requested"

	maxRequestIDBytes  = 96
	maxReasonCodeBytes = 96
	maxWireLineBytes   = contract.MaxDocumentBytes + 1
)

var (
	// ErrInvalidOptions indicates server or client options that cannot safely
	// establish a local administrative boundary.
	ErrInvalidOptions = errors.New("invalid administrative IPC options")
	// ErrDaemonUnavailable indicates that a daemon-owned socket could not be
	// reached without falling back to local state access.
	ErrDaemonUnavailable = errors.New("administrative daemon unavailable")
	// ErrInsecureSocket indicates a socket path that is not a private Unix
	// socket with the required ownership or mode invariants.
	ErrInsecureSocket = errors.New("insecure administrative socket")
	// ErrSocketPathExists indicates that startup refused to replace any
	// existing filesystem object at the configured socket path.
	ErrSocketPathExists = errors.New("administrative socket path already exists")
	// ErrSocketReplaced indicates that the socket path changed after the daemon
	// created it, so further requests were rejected.
	ErrSocketReplaced = errors.New("administrative socket replaced")
	// ErrAlreadyServing indicates that a Server was started or closed already.
	ErrAlreadyServing = errors.New("administrative server already serving")
	// ErrPeerCredentialsUnavailable indicates that the operating system did not
	// provide trustworthy peer credentials for a Unix socket connection.
	ErrPeerCredentialsUnavailable = errors.New("administrative peer credentials unavailable")
	// ErrMalformedRequest indicates a request that cannot be safely routed.
	ErrMalformedRequest = errors.New("malformed administrative request")
	// ErrMalformedResponse indicates a response that cannot be safely consumed.
	ErrMalformedResponse = errors.New("malformed administrative response")
	// ErrRequestRejected indicates that the daemon rejected an authenticated
	// administrative request without making a state change.
	ErrRequestRejected = errors.New("administrative request rejected")
	// ErrIncidentNotFound indicates that an authorized incident show request did
	// not match a durable incident record.
	ErrIncidentNotFound = errors.New("incident not found")
	// ErrResponseTruncated indicates a backup response that ended before its
	// declared snapshot length was received.
	ErrResponseTruncated = errors.New("administrative response truncated")
)

// Operation identifies one daemon-owned administrative request.
type Operation string

const (
	// OperationStatus returns the safe, bounded daemon status view.
	OperationStatus Operation = "status"
	// OperationBackup streams a consistent daemon-owned local-state snapshot.
	OperationBackup Operation = "backup"
	// OperationTargetRegister submits one target document for daemon-owned
	// validation, persistence, and audit.
	OperationTargetRegister Operation = "target.register"
	// OperationRunbookRegister submits one validated typed runbook to the daemon.
	OperationRunbookRegister Operation = "runbook.register"
	// OperationApprovalGrant records one local grant for a waiting recovery command.
	OperationApprovalGrant Operation = "approval.grant"
	// OperationApprovalDeny records one local denial for a waiting recovery command.
	OperationApprovalDeny Operation = "approval.deny"
	OperationIncidentList Operation = "incident.list"
	OperationIncidentShow Operation = "incident.show"
)

// StatusState identifies the lifecycle state returned by an administrative
// status request.
type StatusState string

const (
	// StatusRunning identifies a daemon currently accepting administrative IPC.
	StatusRunning StatusState = "running"
)

// Actor is the operating-system identity attached to an authenticated Unix
// socket peer.
type Actor struct {
	// UID is the authenticated peer's operating-system user identifier.
	UID uint32
	// GID is the authenticated peer's operating-system group identifier.
	GID uint32
}

// Identity returns the bounded audit-safe representation of the actor.
func (a Actor) Identity() string {
	return "uid:" + decimal(a.UID) + "/gid:" + decimal(a.GID)
}

// ApprovalRequest is the strict local IPC payload for one administrator
// decision. The Decision must agree with the selected approval operation.
type ApprovalRequest struct {
	// CommandID identifies one durable recovery command awaiting approval.
	CommandID string `json:"command_id"`
	// Decision is grant or deny for the command.
	Decision contract.ApprovalDecision `json:"decision"`
	// ExpiresAt bounds the approval decision.
	ExpiresAt time.Time `json:"expires_at"`
}

// ApprovalResult is the bounded local IPC response to one persisted decision.
type ApprovalResult struct {
	// SchemaVersion is the response contract version.
	SchemaVersion string `json:"schema_version"`
	// ApprovalID identifies the immutable local decision.
	ApprovalID string `json:"approval_id"`
	// CommandID identifies the command associated with the decision.
	CommandID string `json:"command_id"`
	// Decision is the accepted local grant or denial.
	Decision contract.ApprovalDecision `json:"decision"`
	// CommandState is the durable command state after the decision.
	CommandState contract.RecoveryCommandState `json:"command_state"`
	// ExpiresAt is the persisted decision expiry.
	ExpiresAt time.Time `json:"expires_at"`
}

// Status is the bounded result of an authenticated daemon status request.
type Status struct {
	// SchemaVersion is the status contract version.
	SchemaVersion string `json:"schema_version"`
	// State is the bounded daemon lifecycle state.
	State StatusState `json:"state"`
	// Capabilities lists enabled bounded administrative capabilities.
	Capabilities []string `json:"capabilities"`
	// Unsupported lists explicit standalone limitations.
	Unsupported []string `json:"unsupported"`
}

// Request is one strict, newline-delimited administrative IPC request.
type Request struct {
	// SchemaVersion is the request contract version.
	SchemaVersion string `json:"schema_version"`
	// RequestID correlates a client response without carrying arbitrary input.
	RequestID string `json:"request_id"`
	// Operation selects the daemon-owned administrative action.
	Operation Operation `json:"operation"`
	// ReasonCode is the bounded audit reason for the requested action.
	ReasonCode string `json:"reason_code"`
	// Target is present only for a target registration request.
	Target *contract.ServiceTarget `json:"target,omitempty"`
	// Runbook is present only for a runbook registration request.
	Runbook        *contract.Runbook `json:"runbook,omitempty"`
	Approval       *ApprovalRequest  `json:"approval,omitempty"`
	IncidentFilter *incident.Filter  `json:"incident_filter,omitempty"`
	IncidentID     string            `json:"incident_id,omitempty"`
}

type result string

const (
	resultSuccess result = "success"
	resultFailure result = "failure"
)

type response struct {
	SchemaVersion  string                      `json:"schema_version"`
	RequestID      string                      `json:"request_id,omitempty"`
	Result         result                      `json:"result"`
	ErrorCode      string                      `json:"error_code,omitempty"`
	Status         *Status                     `json:"status,omitempty"`
	BackupSize     int64                       `json:"backup_size,omitempty"`
	TargetResult   *target.RegistrationResult  `json:"target_result,omitempty"`
	RunbookResult  *runbook.RegistrationResult `json:"runbook_result,omitempty"`
	ApprovalResult *ApprovalResult             `json:"approval_result,omitempty"`
	IncidentPage   *incident.Page              `json:"incident_page,omitempty"`
	Incident       *contract.Incident          `json:"incident,omitempty"`
}

func (r Request) validate() error {
	if r.SchemaVersion != SchemaVersion || !validRequestID(r.RequestID) || !validOperation(r.Operation) || !validReasonCode(r.ReasonCode) {
		return ErrMalformedRequest
	}
	switch r.Operation {
	case OperationTargetRegister:
		if r.Target == nil || r.Target.SchemaVersion != SchemaVersion || r.Runbook != nil || r.Approval != nil || r.IncidentFilter != nil || r.IncidentID != "" {
			return ErrMalformedRequest
		}
	case OperationRunbookRegister:
		if r.Runbook == nil || r.Runbook.SchemaVersion != SchemaVersion || r.Target != nil || r.Approval != nil || r.IncidentFilter != nil || r.IncidentID != "" {
			return ErrMalformedRequest
		}
	case OperationApprovalGrant:
		if !validApprovalRequest(r.Approval, contract.ApprovalGranted) || r.Target != nil || r.Runbook != nil || r.IncidentFilter != nil || r.IncidentID != "" {
			return ErrMalformedRequest
		}
	case OperationApprovalDeny:
		if !validApprovalRequest(r.Approval, contract.ApprovalDenied) || r.Target != nil || r.Runbook != nil || r.IncidentFilter != nil || r.IncidentID != "" {
			return ErrMalformedRequest
		}
	case OperationIncidentList:
		if r.IncidentFilter == nil || r.IncidentID != "" || r.Target != nil || r.Runbook != nil || r.Approval != nil || !validIncidentFilter(*r.IncidentFilter) {
			return ErrMalformedRequest
		}
	case OperationIncidentShow:
		if r.IncidentID == "" || r.IncidentFilter != nil || r.Target != nil || r.Runbook != nil || r.Approval != nil {
			return ErrMalformedRequest
		}
	default:
		if r.Target != nil || r.Runbook != nil || r.Approval != nil || r.IncidentFilter != nil || r.IncidentID != "" {
			return ErrMalformedRequest
		}
	}
	return nil
}

func (r response) validate() error {
	if r.SchemaVersion != SchemaVersion || (r.RequestID != "" && !validRequestID(r.RequestID)) {
		return ErrMalformedResponse
	}
	switch r.Result {
	case resultSuccess:
		if r.ErrorCode != "" || responsePayloadCount(r) != 1 {
			return ErrMalformedResponse
		}
	case resultFailure:
		if !validReasonCode(r.ErrorCode) || responsePayloadCount(r) != 0 {
			return ErrMalformedResponse
		}
	default:
		return ErrMalformedResponse
	}
	if r.Status != nil && !r.Status.valid() {
		return ErrMalformedResponse
	}
	if r.BackupSize < 0 || (r.TargetResult != nil && !validTargetResult(*r.TargetResult)) || (r.RunbookResult != nil && !validRunbookResult(*r.RunbookResult)) || (r.ApprovalResult != nil && !validApprovalResult(*r.ApprovalResult)) || (r.IncidentPage != nil && !validIncidentPage(*r.IncidentPage)) || (r.Incident != nil && r.Incident.Validate() != nil) {
		return ErrMalformedResponse
	}
	return nil
}

func responsePayloadCount(value response) int {
	count := 0
	if value.Status != nil {
		count++
	}
	if value.BackupSize != 0 {
		count++
	}
	if value.TargetResult != nil {
		count++
	}
	if value.RunbookResult != nil {
		count++
	}
	if value.ApprovalResult != nil {
		count++
	}
	if value.IncidentPage != nil {
		count++
	}
	if value.Incident != nil {
		count++
	}
	return count
}

func validTargetResult(result target.RegistrationResult) bool {
	if result.SchemaVersion != SchemaVersion || result.Version == 0 || result.TargetID == "" {
		return false
	}
	return true
}

func validRunbookResult(result runbook.RegistrationResult) bool {
	return result.SchemaVersion == SchemaVersion && result.RunbookID != "" && result.Digest != ""
}

func validApprovalRequest(request *ApprovalRequest, decision contract.ApprovalDecision) bool {
	return request != nil && validCode(request.CommandID, maxRequestIDBytes) && request.Decision == decision && !request.ExpiresAt.IsZero()
}

func validApprovalResult(result ApprovalResult) bool {
	return result.SchemaVersion == SchemaVersion && validCode(result.ApprovalID, maxRequestIDBytes) && validCode(result.CommandID, maxRequestIDBytes) && (result.Decision == contract.ApprovalGranted || result.Decision == contract.ApprovalDenied) && (result.CommandState == contract.RecoveryPending || result.CommandState == contract.RecoveryDenied) && !result.ExpiresAt.IsZero()
}

func (s Status) valid() bool {
	if s.SchemaVersion != SchemaVersion || s.State != StatusRunning || len(s.Capabilities) == 0 {
		return false
	}
	for _, capability := range s.Capabilities {
		if !validCode(capability, maxReasonCodeBytes) {
			return false
		}
	}
	for _, unsupported := range s.Unsupported {
		if !validCode(unsupported, maxReasonCodeBytes) {
			return false
		}
	}
	return true
}

func validOperation(operation Operation) bool {
	return operation == OperationStatus || operation == OperationBackup || operation == OperationTargetRegister || operation == OperationRunbookRegister || operation == OperationApprovalGrant || operation == OperationApprovalDeny || operation == OperationIncidentList || operation == OperationIncidentShow
}

func validIncidentFilter(filter incident.Filter) bool {
	return filter.Offset >= 0 && filter.PageSize >= 0 && filter.PageSize <= 100 && (filter.State == "" || filter.State == contract.IncidentOpen || filter.State == contract.IncidentAnalyzing || filter.State == contract.IncidentAwaitingApproval || filter.State == contract.IncidentRecovering || filter.State == contract.IncidentStabilizing || filter.State == contract.IncidentClosed || filter.State == contract.IncidentFailed) && (filter.From.IsZero() || filter.To.IsZero() || !filter.To.Before(filter.From))
}
func validIncidentPage(page incident.Page) bool {
	if page.NextOffset < 0 || len(page.Incidents) > 100 {
		return false
	}
	for _, value := range page.Incidents {
		if value.Validate() != nil {
			return false
		}
	}
	return true
}

func validRequestID(value string) bool {
	return validCode(value, maxRequestIDBytes)
}

func validReasonCode(value string) bool {
	return validCode(value, maxReasonCodeBytes)
}

func validCode(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case bytes.ContainsRune([]byte("._-:/@"), character):
		default:
			return false
		}
	}
	return true
}

func readMessage(reader *bufio.Reader) ([]byte, error) {
	document, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return nil, ErrMalformedRequest
	}
	if err != nil || len(document) == 0 || len(document) > maxWireLineBytes {
		return nil, ErrMalformedRequest
	}
	document = bytes.TrimSuffix(document, []byte{'\n'})
	if len(document) == 0 || len(document) > contract.MaxDocumentBytes {
		return nil, ErrMalformedRequest
	}
	return document, nil
}

func writeMessage(destination io.Writer, value any) error {
	document, err := json.Marshal(value)
	if err != nil || len(document) > contract.MaxDocumentBytes {
		return ErrMalformedResponse
	}
	document = append(document, '\n')
	for len(document) > 0 {
		written, err := destination.Write(document)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		document = document[written:]
	}
	return nil
}

func decodeRequest(document []byte) (Request, error) {
	request, err := contract.Decode(document, contract.DecodeOptions[Request]{
		MaxBytes:      contract.MaxDocumentBytes,
		SchemaVersion: SchemaVersion,
		Validate:      func(value Request) error { return value.validate() },
	})
	if err != nil {
		return Request{}, ErrMalformedRequest
	}
	return request, nil
}

func decodeResponse(document []byte) (response, error) {
	decoded, err := contract.Decode(document, contract.DecodeOptions[response]{
		MaxBytes:      contract.MaxDocumentBytes,
		SchemaVersion: SchemaVersion,
		Validate:      func(value response) error { return value.validate() },
	})
	if err != nil {
		return response{}, ErrMalformedResponse
	}
	return decoded, nil
}

func decimal(value uint32) string {
	if value == 0 {
		return "0"
	}
	var digits [10]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte(value%10) + '0'
		value /= 10
	}
	return string(digits[index:])
}
