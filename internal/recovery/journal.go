package recovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"pulse-agent/internal/contract"
	"pulse-agent/internal/docker"
	"pulse-agent/internal/store"
)

const (
	journalRecordPrefix     = "command/"
	idempotencyIndexPrefix  = "idempotency/"
	maxJournalDocumentBytes = 128 * 1024
)

var errCommandNotExecutable = errors.New("recovery command is not executable")

type journalPhase string

const (
	phasePending          journalPhase = "pending"
	phaseAwaitingApproval journalPhase = "awaiting_approval"
	phaseApproved         journalPhase = "approved"
	phaseExecuting        journalPhase = "executing"
	phaseCompleted        journalPhase = "completed"
	phaseVerifyAndNotify  journalPhase = "verify_and_notify"
)

type journalRecord struct {
	SchemaVersion  string                   `json:"schema_version"`
	Command        contract.RecoveryCommand `json:"command"`
	Target         contract.ServiceTarget   `json:"target"`
	Action         contract.TypedAction     `json:"action"`
	Phase          journalPhase             `json:"phase"`
	Reconciliation *reconciliation          `json:"reconciliation,omitempty"`
}

type reconciliation struct {
	ObservedAt time.Time       `json:"observed_at"`
	Verified   bool            `json:"verified"`
	Snapshot   docker.Snapshot `json:"snapshot"`
}

type storedRecord struct {
	key    string
	record journalRecord
}

func (c *Coordinator) persistPending(record journalRecord) (journalRecord, bool, error) {
	key := recordKey(record.Command)
	indexKey := idempotencyIndexKey(record.Command.IdempotencyKey)
	var (
		persisted journalRecord
		duplicate bool
	)
	err := c.state.Update(func(tx *store.Tx) error {
		indexedRecordKey, indexed, err := tx.Get(store.BucketCommandJournal, indexKey)
		if err != nil {
			return err
		}
		if indexed {
			if string(indexedRecordKey) != key {
				return ErrIdempotencyConflict
			}
			existing, found, err := loadRecord(tx, key)
			if err != nil {
				return err
			}
			if !found {
				return ErrCorruptJournal
			}
			persisted = existing
			duplicate = true
			return nil
		}

		existing, found, err := loadRecord(tx, key)
		if err != nil {
			return err
		}
		if found {
			if err := tx.Put(store.BucketCommandJournal, indexKey, []byte(key)); err != nil {
				return err
			}
			persisted = existing
			duplicate = true
			return nil
		}
		if err := putRecord(tx, key, record); err != nil {
			return err
		}
		if err := tx.Put(store.BucketCommandJournal, indexKey, []byte(key)); err != nil {
			return err
		}
		persisted = record
		return nil
	})
	if err != nil {
		return journalRecord{}, false, fmt.Errorf("persist recovery command: %w", err)
	}
	return persisted, duplicate, nil
}

func (c *Coordinator) deny(key string) (journalRecord, error) {
	return c.updateRecord(key, func(record *journalRecord) error {
		if record.Phase != phasePending || record.Command.State != contract.RecoveryPending {
			return errCommandNotExecutable
		}
		if err := record.Command.State.ValidateTransition(contract.RecoveryDenied); err != nil {
			return err
		}
		record.Command.State = contract.RecoveryDenied
		record.Phase = phaseCompleted
		return nil
	})
}

func (c *Coordinator) expire(key string) (journalRecord, error) {
	return c.updateRecord(key, func(record *journalRecord) error {
		if record.Phase != phasePending || record.Command.State != contract.RecoveryPending {
			return errCommandNotExecutable
		}
		if err := record.Command.State.ValidateTransition(contract.RecoveryExpired); err != nil {
			return err
		}
		record.Command.State = contract.RecoveryExpired
		record.Phase = phaseCompleted
		return nil
	})
}

func (c *Coordinator) approve(key string) (journalRecord, error) {
	return c.updateRecord(key, func(record *journalRecord) error {
		if record.Phase != phasePending || record.Command.State != contract.RecoveryPending {
			return errCommandNotExecutable
		}
		if err := record.Command.State.ValidateTransition(contract.RecoveryApproved); err != nil {
			return err
		}
		record.Command.State = contract.RecoveryApproved
		record.Phase = phaseApproved
		return nil
	})
}

func (c *Coordinator) startExecution(key string) (journalRecord, error) {
	return c.updateRecord(key, func(record *journalRecord) error {
		if record.Phase != phaseApproved || record.Command.State != contract.RecoveryApproved {
			return errCommandNotExecutable
		}
		if err := record.Command.State.ValidateTransition(contract.RecoveryExecuting); err != nil {
			return err
		}
		record.Command.State = contract.RecoveryExecuting
		record.Phase = phaseExecuting
		return nil
	})
}

func (c *Coordinator) finishExecution(key string, next contract.RecoveryCommandState) (journalRecord, error) {
	if next != contract.RecoverySucceeded && next != contract.RecoveryFailed {
		return journalRecord{}, ErrInvalidRequest
	}
	return c.updateRecord(key, func(record *journalRecord) error {
		if record.Phase != phaseExecuting || record.Command.State != contract.RecoveryExecuting {
			return errCommandNotExecutable
		}
		if err := record.Command.State.ValidateTransition(next); err != nil {
			return err
		}
		record.Command.State = next
		record.Phase = phaseCompleted
		return nil
	})
}

func (c *Coordinator) markVerifyAndNotify(key string, snapshot docker.Snapshot, verified bool, now time.Time) (journalRecord, error) {
	return c.updateRecord(key, func(record *journalRecord) error {
		if !isReconcilablePhase(record.Phase) {
			return errCommandNotExecutable
		}
		if verified && snapshot.TargetID != record.Command.TargetID {
			verified = false
			snapshot = docker.Snapshot{}
		}
		record.Phase = phaseVerifyAndNotify
		record.Reconciliation = &reconciliation{ObservedAt: now, Verified: verified, Snapshot: snapshot}
		return nil
	})
}

func (c *Coordinator) updateRecord(key string, update func(*journalRecord) error) (journalRecord, error) {
	if update == nil {
		return journalRecord{}, ErrInvalidRequest
	}
	var updated journalRecord
	err := c.state.Update(func(tx *store.Tx) error {
		record, found, err := loadRecord(tx, key)
		if err != nil {
			return err
		}
		if !found {
			return ErrCorruptJournal
		}
		if err := update(&record); err != nil {
			return err
		}
		if err := putRecord(tx, key, record); err != nil {
			return err
		}
		updated = record
		return nil
	})
	if err != nil {
		return journalRecord{}, fmt.Errorf("update recovery command: %w", err)
	}
	return updated, nil
}

func (c *Coordinator) reconcilableRecords() ([]storedRecord, error) {
	records := make([]storedRecord, 0)
	err := c.state.View(func(tx *store.Tx) error {
		return tx.ForEach(store.BucketCommandJournal, func(key string, document []byte) error {
			if !strings.HasPrefix(key, journalRecordPrefix) {
				return nil
			}
			record, err := decodeRecord(document)
			if err != nil {
				return err
			}
			if recordKey(record.Command) != key {
				return ErrCorruptJournal
			}
			if isReconcilablePhase(record.Phase) {
				records = append(records, storedRecord{key: key, record: record})
			}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("read recovery journal: %w", err)
	}
	return records, nil
}

func loadRecord(tx *store.Tx, key string) (journalRecord, bool, error) {
	document, found, err := tx.Get(store.BucketCommandJournal, key)
	if err != nil || !found {
		return journalRecord{}, found, err
	}
	record, err := decodeRecord(document)
	if err != nil {
		return journalRecord{}, false, err
	}
	if recordKey(record.Command) != key {
		return journalRecord{}, false, ErrCorruptJournal
	}
	return record, true, nil
}

func putRecord(tx *store.Tx, key string, record journalRecord) error {
	if recordKey(record.Command) != key || validateRecord(record) != nil {
		return ErrCorruptJournal
	}
	document, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode recovery command: %w", err)
	}
	return tx.Put(store.BucketCommandJournal, key, document)
}

func decodeRecord(document []byte) (journalRecord, error) {
	record, err := contract.Decode(document, contract.DecodeOptions[journalRecord]{
		MaxBytes:      maxJournalDocumentBytes,
		SchemaVersion: contract.SchemaVersionV1,
		Validate:      validateRecord,
	})
	if err != nil {
		return journalRecord{}, ErrCorruptJournal
	}
	return record, nil
}

func validateRecord(record journalRecord) error {
	command := record.Command
	if record.SchemaVersion != contract.SchemaVersionV1 || command.Validate() != nil || !validToken(command.CommandID, maxCommandIDLength) || !validToken(command.IncidentID, maxCommandIDLength) || !validToken(command.RunbookID, maxCommandIDLength) || !validToken(command.RunbookDigest, maxIdempotencyKeyLength) || !validToken(command.TargetID, maxCommandIDLength) || !validToken(command.IdempotencyKey, maxIdempotencyKeyLength) || (command.ApprovalID != "" && !validToken(command.ApprovalID, maxCommandIDLength)) || !validRiskTier(command.RiskTier) {
		return ErrCorruptJournal
	}
	if record.Target.SchemaVersion != contract.SchemaVersionV1 || record.Target.TargetID != command.TargetID || record.Target.AdapterType != docker.AdapterType || !record.Target.Enabled || !validToken(record.Target.Selector, maxIdempotencyKeyLength) {
		return ErrCorruptJournal
	}
	if !validAction(record.Action, record.Target.Selector) || !validRecordPhase(record.Phase, command.State) {
		return ErrCorruptJournal
	}
	if record.Phase == phaseVerifyAndNotify {
		if record.Reconciliation == nil || record.Reconciliation.ObservedAt.IsZero() {
			return ErrCorruptJournal
		}
		if record.Reconciliation.Verified && record.Reconciliation.Snapshot.TargetID != command.TargetID {
			return ErrCorruptJournal
		}
		if !record.Reconciliation.Verified && record.Reconciliation.Snapshot != (docker.Snapshot{}) {
			return ErrCorruptJournal
		}
		return nil
	}
	if record.Reconciliation != nil {
		return ErrCorruptJournal
	}
	return nil
}

func validRecordPhase(phase journalPhase, state contract.RecoveryCommandState) bool {
	switch phase {
	case phasePending, phaseAwaitingApproval:
		return state == contract.RecoveryPending
	case phaseApproved:
		return state == contract.RecoveryApproved
	case phaseExecuting:
		return state == contract.RecoveryExecuting
	case phaseCompleted:
		return state == contract.RecoverySucceeded || state == contract.RecoveryFailed || state == contract.RecoveryDenied || state == contract.RecoveryExpired
	case phaseVerifyAndNotify:
		return state == contract.RecoveryPending || state == contract.RecoveryApproved || state == contract.RecoveryExecuting
	default:
		return false
	}
}

func validRiskTier(risk contract.RiskTier) bool {
	return risk == contract.RiskLow || risk == contract.RiskMedium || risk == contract.RiskHigh
}

func validAction(action contract.TypedAction, selector string) bool {
	if action.TargetSelector != selector || action.StopTimeout.Value() <= 0 || action.Cooldown.Value() < 0 {
		return false
	}
	return action.ActionType == contract.ActionDockerContainerRestart || action.ActionType == contract.ActionDockerComposeServiceRestart
}

func isReconcilablePhase(phase journalPhase) bool {
	return phase == phasePending || phase == phaseApproved || phase == phaseExecuting
}

func recordKey(command contract.RecoveryCommand) string {
	return stableKey(journalRecordPrefix, command.IncidentID, command.RunbookID, command.RunbookDigest, command.TargetID, strconv.Itoa(command.ActionIndex))
}

func idempotencyIndexKey(idempotencyKey string) string {
	return stableKey(idempotencyIndexPrefix, idempotencyKey)
}

func stableKey(prefix string, values ...string) string {
	identity := strings.Join(values, "\x00") + "\x00"
	sum := sha256.Sum256([]byte(identity))
	return prefix + hex.EncodeToString(sum[:])
}
