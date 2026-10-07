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

type finalizeFixture struct {
	passes    *Service
	recorder  *recorder.Manager
	unlocker  *receiver.Unlocker
	trail     *audit.Trail
	finalizer *Finalizer
}

func newFinalizeFixture(t *testing.T) finalizeFixture {
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
	unlocker := receiver.NewUnlocker(trail)
	return finalizeFixture{
		passes: passes, recorder: manager, unlocker: unlocker, trail: trail,
		finalizer: NewFinalizer(passes, manager, unlocker, trail, 50*time.Millisecond),
	}
}

func (f finalizeFixture) newTrackingPass(t *testing.T) Pass {
	t.Helper()
	value, err := f.passes.Create(CreateRequest{
		SatelliteID: "SAT-A12", AntennaID: "ANT-01",
		RFChains: []string{"RF-01"}, RequiredReceiverChains: []string{"RF-01"},
		AOS: time.Now().UTC(), LOS: time.Now().UTC().Add(8 * time.Minute),
		Revision: 1, OwnerStation: "north",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.passes.BeginAcquisition(value.ID, "attempt-1"); err != nil {
		t.Fatal(err)
	}
	decision, err := f.passes.AcceptDiversity(value.ID, []receiver.AcquisitionResult{
		{PassID: value.ID, AttemptID: "attempt-1", ChainID: "RF-01", Locked: true, Synced: true, Epoch: 7},
	})
	if err != nil || !decision.Ready {
		t.Fatalf("diversity did not converge: %#v %v", decision, err)
	}
	value, _ = f.passes.Get(value.ID)
	return value
}

func TestFinalizeUnlockTimeoutStopsRecoverable(t *testing.T) {
	fixture := newFinalizeFixture(t)
	value := fixture.newTrackingPass(t)
	if err := fixture.recorder.Buffer(value.RecordingSegmentID, recorder.Frame{Sequence: 1, Payload: []byte("frame-one")}); err != nil {
		t.Fatal(err)
	}
	fixture.unlocker.SetDelay("RF-01", 500*time.Millisecond)
	result, err := fixture.finalizer.Finalize(context.Background(), value.ID, "RF-01")
	if err == nil {
		t.Fatal("finalize unexpectedly succeeded while the receiver chain was locked")
	}
	if result.UnlockError == "" {
		t.Fatal("unlock error was not captured in the result")
	}
	current, _ := fixture.passes.Get(value.ID)
	if current.Phase != Draining {
		t.Fatalf("pass phase = %s, want %s", current.Phase, Draining)
	}
	segment, found := fixture.recorder.ActiveForPass(value.ID)
	if !found || segment.Status != recorder.Open {
		t.Fatalf("segment status = %v (found %v), want open", segment.Status, found)
	}
	if segment.FramesBuffered != 1 {
		t.Fatalf("buffered frames = %d, want 1 (drain must not run while the chain is locked)", segment.FramesBuffered)
	}
	blocked := false
	for _, event := range fixture.trail.List(audit.Query{Component: "pass", Subject: value.ID}) {
		if event.Action == "finalize.blocked" && event.Severity == audit.Warning {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("blocked finalize was not audited")
	}

	fixture.unlocker.SetDelay("RF-01", 0)
	result, err = fixture.finalizer.Finalize(context.Background(), value.ID, "RF-01")
	if err != nil {
		t.Fatalf("retry from the recoverable stage failed: %v", err)
	}
	if result.FramesDrained != 1 || !result.Seal.Complete {
		t.Fatalf("retry result = %#v, want 1 drained frame and a complete seal", result)
	}
	current, _ = fixture.passes.Get(value.ID)
	if current.Phase != Completed {
		t.Fatalf("pass phase = %s, want %s", current.Phase, Completed)
	}
	if _, found := fixture.recorder.ActiveForPass(value.ID); found {
		t.Fatal("recording segment still active after finalize")
	}
}

func TestFinalizeRejectsTerminalPhase(t *testing.T) {
	fixture := newFinalizeFixture(t)
	value := fixture.newTrackingPass(t)
	if _, err := fixture.finalizer.Finalize(context.Background(), value.ID, "RF-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.finalizer.Finalize(context.Background(), value.ID, "RF-01"); err == nil {
		t.Fatal("re-finalizing a completed pass unexpectedly succeeded")
	}
	current, _ := fixture.passes.Get(value.ID)
	if current.Phase != Completed {
		t.Fatalf("pass phase = %s, want %s (terminal phase must not be rewritten)", current.Phase, Completed)
	}
}

func TestFinalizeRejectsCanceledPass(t *testing.T) {
	fixture := newFinalizeFixture(t)
	value := fixture.newTrackingPass(t)
	if err := fixture.passes.Cancel(value.ID, "operator abort"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.finalizer.Finalize(context.Background(), value.ID, "RF-01"); err == nil {
		t.Fatal("finalizing a canceled pass unexpectedly succeeded")
	}
	current, _ := fixture.passes.Get(value.ID)
	if current.Phase != Canceled {
		t.Fatalf("pass phase = %s, want %s", current.Phase, Canceled)
	}
}
