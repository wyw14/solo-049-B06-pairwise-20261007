package pass

import (
	"context"
	"fmt"
	"time"

	"orbitlink/internal/audit"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
)

type FinalizeResult struct {
	PassID        string              `json:"pass_id"`
	FramesDrained int                 `json:"frames_drained"`
	Seal          recorder.SealResult `json:"seal"`
}

type Finalizer struct {
	passes        *Service
	recorder      *recorder.Manager
	unlocker      *receiver.Unlocker
	audit         *audit.Trail
	unlockTimeout time.Duration
}

func NewFinalizer(passes *Service, manager *recorder.Manager, unlocker *receiver.Unlocker, trail *audit.Trail, unlockTimeout time.Duration) *Finalizer {
	if unlockTimeout <= 0 {
		unlockTimeout = 250 * time.Millisecond
	}
	return &Finalizer{passes: passes, recorder: manager, unlocker: unlocker, audit: trail, unlockTimeout: unlockTimeout}
}

// Finalize takes a tracking pass to Completed. The receiver unlock is a hard
// safety gate: while the chain may still be locked, no frames may be drained or
// sealed and the pass must not read Completed. On any failure the pass is left
// in Draining (a recoverable phase) with the reason recorded, so finalize can
// be retried once the chain responds.
func (f *Finalizer) Finalize(ctx context.Context, passID, chainID string) (FinalizeResult, error) {
	value, found := f.passes.Get(passID)
	if !found {
		return FinalizeResult{}, fmt.Errorf("pass %s not found", passID)
	}
	if value.RecordingSegmentID == "" {
		return FinalizeResult{}, fmt.Errorf("pass %s has no recording segment", passID)
	}
	if err := f.passes.BeginFinalize(passID); err != nil {
		return FinalizeResult{}, err
	}

	// Gate 1: the receiver chain must confirm unlock before anything else.
	unlockContext, cancelUnlock := context.WithTimeout(ctx, f.unlockTimeout)
	err := f.unlocker.Unlock(unlockContext, chainID, passID)
	cancelUnlock()
	if err != nil {
		return f.abort(passID, "unlock", err)
	}

	// Gate 2: flush every buffered frame. Drain is resumable, so a canceled
	// deadline leaves committed frames durable and the rest for a retry.
	drained, err := f.recorder.Drain(ctx, value.RecordingSegmentID)
	result := FinalizeResult{PassID: passID, FramesDrained: drained}
	if err != nil {
		return f.abort(passID, "drain", err)
	}

	// Gate 3: seal refuses anything that is still open or holds buffered
	// frames, so a seal error here means the recording is not finalized.
	seal, err := f.recorder.Seal(value.RecordingSegmentID, "pass LOS complete")
	result.Seal = seal
	if err != nil {
		return f.abort(passID, "seal", err)
	}

	// Gate 4: only a durably sealed recording may move the pass to Completed.
	if err := f.passes.CompleteFinalize(passID, value.RecordingSegmentID); err != nil {
		return f.abort(passID, "complete", err)
	}

	_, _ = f.audit.Record(audit.Event{Component: "pass", Action: "finalized", Subject: passID, Fields: map[string]any{"frames_drained": drained, "chain_id": chainID}})
	return result, nil
}

// abort records why finalization stopped and leaves the pass recoverable in
// Draining rather than falsely Completed.
func (f *Finalizer) abort(passID, stage string, cause error) (FinalizeResult, error) {
	reason := stage + ": " + cause.Error()
	_ = f.passes.FailFinalize(passID, reason)
	_, _ = f.audit.Record(audit.Event{Component: "pass", Action: "finalize.incomplete", Subject: passID, Severity: audit.Warning, Fields: map[string]any{"stage": stage, "error": cause.Error()}})
	return FinalizeResult{PassID: passID}, fmt.Errorf("finalize pass %s halted at %s: %w", passID, stage, cause)
}
