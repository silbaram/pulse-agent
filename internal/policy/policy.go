// Package policy provides pure, deterministic recovery authorization decisions.
package policy

import (
	"sort"
	"time"

	"pulse-agent/internal/contract"
)

// Verdict identifies the only outcomes a policy evaluation can produce.
type Verdict string

const (
	// VerdictAllow identifies a fully authorized recovery action.
	VerdictAllow Verdict = "allow"
	// VerdictAwaitApproval identifies a recovery action that needs a valid human approval.
	VerdictAwaitApproval Verdict = "await_approval"
	// VerdictDeny identifies a recovery action that must not change state.
	VerdictDeny Verdict = "deny"
)

// ReasonCode identifies a stable, deterministic policy outcome reason.
type ReasonCode string

const (
	// ReasonAllowed identifies a fully satisfied recovery policy.
	ReasonAllowed ReasonCode = "allowed"
	// ReasonApprovalRequired identifies a recovery waiting for a valid approval.
	ReasonApprovalRequired ReasonCode = "approval_required"
	// ReasonUnregisteredRunbook identifies a requested runbook outside the snapshot.
	ReasonUnregisteredRunbook ReasonCode = "unregistered_runbook"
	// ReasonForgedDigest identifies a requested digest that does not match registration.
	ReasonForgedDigest ReasonCode = "forged_digest"
	// ReasonTargetMismatch identifies a recovery requested for another target.
	ReasonTargetMismatch ReasonCode = "target_mismatch"
	// ReasonActionInvalid identifies an action index outside a registered runbook.
	ReasonActionInvalid ReasonCode = "action_invalid"
	// ReasonAnalysisUnavailable identifies a required analysis that did not complete safely.
	ReasonAnalysisUnavailable ReasonCode = "analysis_unavailable"
	// ReasonAnalysisMismatch identifies analysis that did not recommend this registered runbook.
	ReasonAnalysisMismatch ReasonCode = "analysis_runbook_mismatch"
	// ReasonPreconditionFailed identifies an unmet registered precondition.
	ReasonPreconditionFailed ReasonCode = "precondition_failed"
	// ReasonCooldownActive identifies a restart action still in its configured cooldown.
	ReasonCooldownActive ReasonCode = "cooldown_active"
	// ReasonRetryExhausted identifies an exhausted registered retry budget.
	ReasonRetryExhausted ReasonCode = "retry_exhausted"
	// ReasonStabilizationInvalid identifies a missing or unsafe stabilization policy.
	ReasonStabilizationInvalid ReasonCode = "stabilization_invalid"
	// ReasonApprovalExpired identifies an approval that cannot authorize execution anymore.
	ReasonApprovalExpired ReasonCode = "approval_expired"
	// ReasonApprovalRevoked identifies a revoked or unauthorized approver.
	ReasonApprovalRevoked ReasonCode = "approval_revoked"
	// ReasonApprovalDenied identifies an explicit human denial.
	ReasonApprovalDenied ReasonCode = "approval_denied"
	// ReasonInvalidPolicy identifies a malformed snapshot or evaluation input.
	ReasonInvalidPolicy ReasonCode = "invalid_policy"
)

// RegisteredRunbook is one immutable registration visible to the policy engine.
type RegisteredRunbook struct {
	Runbook          contract.Runbook
	TargetID         string
	AnalysisRequired bool
}

// Snapshot is the complete policy input supplied by the local registry. Callers
// must not mutate its slices while Evaluate is reading the snapshot.
type Snapshot struct {
	Runbooks            []RegisteredRunbook
	AuthorizedApprovers []string
}

// Input is the dynamic, non-mutating context for one requested recovery action.
type Input struct {
	RunbookID              string
	RunbookDigest          string
	TargetID               string
	ActionIndex            int
	CommandID              string
	AnalysisAvailable      bool
	AnalysisCandidateIDs   []string
	AnalysisConfidence     []contract.ConfidenceLabel
	NotificationSuggestion contract.NotificationRecommendation
	Preconditions          map[string]bool
	LastAttemptAt          time.Time
	Now                    time.Time
	AttemptCount           int
	Approval               *contract.Approval
	ApprovalRevoked        bool
}

// Decision is a deterministic authorization outcome with no execution capability.
type Decision struct {
	Verdict    Verdict
	ReasonCode ReasonCode
}

// Evaluate returns the same decision for the same snapshot and input. It has no
// Docker, model, clock, persistence, network, or mutable global dependency.
func Evaluate(snapshot Snapshot, input Input) Decision {
	registered, reason := registeredRunbook(snapshot, input)
	if reason != "" {
		return deny(reason)
	}
	runbook := registered.Runbook
	if input.RunbookDigest != runbook.Digest {
		return deny(ReasonForgedDigest)
	}
	if input.TargetID != registered.TargetID {
		return deny(ReasonTargetMismatch)
	}
	if input.ActionIndex < 0 || input.ActionIndex >= len(runbook.TypedActions) {
		return deny(ReasonActionInvalid)
	}
	if registered.AnalysisRequired {
		if !input.AnalysisAvailable {
			return deny(ReasonAnalysisUnavailable)
		}
		if !contains(input.AnalysisCandidateIDs, runbook.RunbookID) {
			return deny(ReasonAnalysisMismatch)
		}
	}
	if !preconditionsMet(runbook.Preconditions, input.Preconditions) {
		return deny(ReasonPreconditionFailed)
	}
	action := runbook.TypedActions[input.ActionIndex]
	if !cooldownElapsed(action.Cooldown.Value(), input.LastAttemptAt, input.Now) {
		return deny(ReasonCooldownActive)
	}
	if input.AttemptCount < 0 || input.AttemptCount >= runbook.RetryPolicy.MaxAttempts {
		return deny(ReasonRetryExhausted)
	}
	if runbook.StabilizationPolicy.RecoverySamples < 1 || runbook.StabilizationPolicy.Window.Value() <= 0 {
		return deny(ReasonStabilizationInvalid)
	}
	approvalDecision := approval(snapshot.AuthorizedApprovers, input)
	if approvalDecision.ReasonCode != "" {
		return approvalDecision
	}
	if needsApproval(runbook) {
		return Decision{Verdict: VerdictAwaitApproval, ReasonCode: ReasonApprovalRequired}
	}
	return Decision{Verdict: VerdictAllow, ReasonCode: ReasonAllowed}
}

func registeredRunbook(snapshot Snapshot, input Input) (RegisteredRunbook, ReasonCode) {
	if !validSnapshot(snapshot) || input.RunbookID == "" || input.RunbookDigest == "" || input.TargetID == "" || input.CommandID == "" {
		return RegisteredRunbook{}, ReasonInvalidPolicy
	}
	for _, registered := range snapshot.Runbooks {
		if registered.Runbook.RunbookID == input.RunbookID {
			return registered, ""
		}
	}
	return RegisteredRunbook{}, ReasonUnregisteredRunbook
}

func validSnapshot(snapshot Snapshot) bool {
	if len(snapshot.Runbooks) == 0 {
		return false
	}
	seenRunbooks := make(map[string]struct{}, len(snapshot.Runbooks))
	for _, registered := range snapshot.Runbooks {
		runbook := registered.Runbook
		if registered.TargetID == "" || runbook.SchemaVersion != contract.SchemaVersionV1 || runbook.RunbookID == "" || runbook.Digest == "" || len(runbook.TypedActions) == 0 || runbook.RetryPolicy.MaxAttempts < 1 || (runbook.RiskTier != contract.RiskLow && runbook.RiskTier != contract.RiskMedium && runbook.RiskTier != contract.RiskHigh) {
			return false
		}
		for _, action := range runbook.TypedActions {
			if (action.ActionType != contract.ActionDockerContainerRestart && action.ActionType != contract.ActionDockerComposeServiceRestart) || action.TargetSelector == "" || action.StopTimeout.Value() <= 0 || action.Cooldown.Value() < 0 {
				return false
			}
		}
		if _, duplicate := seenRunbooks[runbook.RunbookID]; duplicate {
			return false
		}
		seenRunbooks[runbook.RunbookID] = struct{}{}
	}
	return uniqueNonEmpty(snapshot.AuthorizedApprovers)
}

func preconditionsMet(required []string, observed map[string]bool) bool {
	if !uniqueNonEmpty(required) {
		return false
	}
	for _, condition := range required {
		if !observed[condition] {
			return false
		}
	}
	return true
}

func cooldownElapsed(cooldown time.Duration, previous, now time.Time) bool {
	if cooldown < 0 || previous.IsZero() {
		return cooldown >= 0
	}
	return !now.IsZero() && !now.Before(previous) && now.Sub(previous) >= cooldown
}

func approval(authorized []string, input Input) Decision {
	if input.Approval == nil {
		return Decision{}
	}
	approval := *input.Approval
	if input.ApprovalRevoked || !contains(authorized, approval.ApproverIdentity) {
		return deny(ReasonApprovalRevoked)
	}
	if approval.Decision == contract.ApprovalDenied {
		return deny(ReasonApprovalDenied)
	}
	if approval.SchemaVersion != contract.SchemaVersionV1 || approval.ApprovalID == "" || approval.Decision != contract.ApprovalGranted || approval.CommandID != input.CommandID || approval.CreatedAt.IsZero() || approval.ExpiresAt.IsZero() || !approval.ExpiresAt.After(approval.CreatedAt) || input.Now.IsZero() || !input.Now.Before(approval.ExpiresAt) {
		return deny(ReasonApprovalExpired)
	}
	return Decision{Verdict: VerdictAllow, ReasonCode: ReasonAllowed}
}

func needsApproval(runbook contract.Runbook) bool {
	return runbook.RiskTier != contract.RiskLow || runbook.ApprovalPolicy.Required || !runbook.AutoExecute
}

func uniqueNonEmpty(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func contains(values []string, want string) bool {
	values = append([]string(nil), values...)
	sort.Strings(values)
	index := sort.SearchStrings(values, want)
	return index < len(values) && values[index] == want
}

func deny(reason ReasonCode) Decision {
	return Decision{Verdict: VerdictDeny, ReasonCode: reason}
}
