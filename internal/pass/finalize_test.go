package pass

import (
	"context"
	"testing"
	"time"

	"orbitlink/internal/audit"
	"orbitlink/internal/receiver"
	"orbitlink/internal/recorder"
	"orbitlink/internal/store"
)

func newFinalizerFixture(t *testing.T) (*Service, *recorder.Manager, *receiver.Unlocker, *Finalizer, Pass) {
	t.Helper()
	paths := store.NewPaths(t.TempDir())
	trail := audit.NewTrail(store.NewAppendLog(paths))
	manager, err := recorder.NewManager(paths, trail)
	if err != nil {
		t.Fatal(err)
	}
	passes, err := NewService(paths, manager, trail)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	value, err := passes.Create(CreateRequest{
		SatelliteID: "SAT-1", AntennaID: "ANT-1",
		RFChains: []string{"RF-01", "RF-02"}, RequiredReceiverChains: []string{"RF-01", "RF-02"},
		AOS: now.Add(-time.Minute), LOS: now.Add(time.Minute), Revision: 1, OwnerStation: "north",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := passes.BeginAcquisition(value.ID, "attempt-1"); err != nil {
		t.Fatal(err)
	}
	decision, err := passes.AcceptDiversity(value.ID, []receiver.AcquisitionResult{
		{PassID: value.ID, AttemptID: "attempt-1", ChainID: "RF-01", Locked: true, Synced: true, Epoch: 1},
		{PassID: value.ID, AttemptID: "attempt-1", ChainID: "RF-02", Locked: true, Synced: true, Epoch: 1},
	})
	if err != nil || !decision.Ready {
		t.Fatalf("diversity did not converge: %#v %v", decision, err)
	}
	value, _ = passes.Get(value.ID)
	unlocker := receiver.NewUnlocker(trail)
	finalizer := NewFinalizer(passes, manager, unlocker, trail, 40*time.Millisecond)
	return passes, manager, unlocker, finalizer, value
}

// A receiver that does not unlock in time must halt finalization before any
// frame is drained or sealed and leave the pass recoverable (Draining), not
// falsely Completed with the chain still locked.
func TestFinalizeStopsAtUnlockTimeoutAndRetries(t *testing.T) {
	passes, manager, unlocker, finalizer, value := newFinalizerFixture(t)

	for sequence := uint64(0); sequence < 3; sequence++ {
		if err := manager.Buffer(value.RecordingSegmentID, recorder.Frame{Sequence: sequence, Epoch: 1, Payload: []byte("frame-payload")}); err != nil {
			t.Fatal(err)
		}
	}

	// Receiver chain responds far slower than the unlock deadline.
	unlocker.SetDelay("RF-01", 300*time.Millisecond)
	result, err := finalizer.Finalize(context.Background(), value.ID, "RF-01")
	if err == nil {
		t.Fatal("finalize unexpectedly succeeded with an unresponsive receiver")
	}

	current, _ := passes.Get(value.ID)
	if current.Phase != Draining {
		t.Fatalf("pass phase = %s, want recoverable %s after unlock failure", current.Phase, Draining)
	}
	if current.FailureReason == "" {
		t.Fatal("expected failure reason to be recorded for the halted finalize")
	}

	segment, _ := manager.Segment(value.RecordingSegmentID)
	if segment.Status != recorder.Open {
		t.Fatalf("segment status = %s, want open; drain must not run before unlock", segment.Status)
	}
	if segment.FramesBuffered != 3 || segment.FramesWritten != 0 {
		t.Fatalf("frames buffered=%d written=%d, want 3 buffered and 0 written", segment.FramesBuffered, segment.FramesWritten)
	}
	if result.Seal.Complete {
		t.Fatal("recording must not be sealed when unlock fails")
	}

	// Chain is reachable on retry: finalize resumes from Draining and finishes.
	unlocker.SetDelay("RF-01", 0)
	result, err = finalizer.Finalize(context.Background(), value.ID, "RF-01")
	if err != nil {
		t.Fatalf("retry finalize failed: %v", err)
	}
	if result.FramesDrained != 3 || !result.Seal.Complete {
		t.Fatalf("retry result = %#v, want 3 frames drained and a complete seal", result)
	}
	current, _ = passes.Get(value.ID)
	if current.Phase != Completed {
		t.Fatalf("pass phase = %s, want %s after successful retry", current.Phase, Completed)
	}
	if current.FailureReason != "" {
		t.Fatalf("stale failure reason retained: %q", current.FailureReason)
	}
	segment, _ = manager.Segment(value.RecordingSegmentID)
	if segment.Status != recorder.Sealed || segment.FramesWritten != 3 || segment.FramesBuffered != 0 {
		t.Fatalf("segment after retry = %#v, want sealed with 3 frames written", segment)
	}
}

// A pass that never reached tracking cannot be driven to completion.
func TestFinalizeRejectsUntrackedPass(t *testing.T) {
	paths := store.NewPaths(t.TempDir())
	trail := audit.NewTrail(store.NewAppendLog(paths))
	manager, err := recorder.NewManager(paths, trail)
	if err != nil {
		t.Fatal(err)
	}
	passes, err := NewService(paths, manager, trail)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	value, err := passes.Create(CreateRequest{
		SatelliteID: "SAT-1", AntennaID: "ANT-1",
		RFChains: []string{"RF-01"}, RequiredReceiverChains: []string{"RF-01"},
		AOS: now.Add(-time.Minute), LOS: now.Add(time.Minute), Revision: 1, OwnerStation: "north",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Give it a segment without entering tracking, then attempt completion.
	segment, err := manager.Start(value.ID, value.OwnerStation, value.OwnerGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if err := passes.update(value.ID, func(current *Pass) error { current.RecordingSegmentID = segment.ID; return nil }); err != nil {
		t.Fatal(err)
	}
	finalizer := NewFinalizer(passes, manager, receiver.NewUnlocker(trail), trail, time.Second)
	if _, err := finalizer.Finalize(context.Background(), value.ID, "RF-01"); err == nil {
		t.Fatal("finalize unexpectedly succeeded from planned phase")
	}
	current, _ := passes.Get(value.ID)
	if current.Phase != Planned {
		t.Fatalf("pass phase = %s, want planned untouched", current.Phase)
	}
}
