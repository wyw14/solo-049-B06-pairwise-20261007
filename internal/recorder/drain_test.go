package recorder

import (
	"context"
	"errors"
	"testing"

	"orbitlink/internal/audit"
	"orbitlink/internal/store"
)

func newDrainFixture(t *testing.T) (*Manager, string, *FrameWriter) {
	t.Helper()
	paths := store.NewPaths(t.TempDir())
	trail := audit.NewTrail(store.NewAppendLog(paths))
	manager, err := NewManager(paths, trail)
	if err != nil {
		t.Fatal(err)
	}
	segment, err := manager.Start("pass-1", "north", 1)
	if err != nil {
		t.Fatal(err)
	}
	return manager, segment.ID, manager.writer
}

func bufferFrames(t *testing.T, manager *Manager, segmentID string, n int) {
	t.Helper()
	for sequence := 0; sequence < n; sequence++ {
		if err := manager.Buffer(segmentID, Frame{Sequence: uint64(sequence), Epoch: 1, Payload: []byte("payload-bytes")}); err != nil {
			t.Fatal(err)
		}
	}
}

// A drain stopped by cancellation must leave the segment recoverable in
// Draining with every frame still buffered; a subsequent drain completes
// without appending any frame twice.
func TestDrainResumesAfterCancellation(t *testing.T) {
	manager, segmentID, writer := newDrainFixture(t)
	bufferFrames(t, manager, segmentID, 4)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	written, err := manager.Drain(canceled, segmentID)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("drain err = %v, want context.Canceled", err)
	}
	if written != 0 {
		t.Fatalf("wrote %d frames under an already-canceled context, want 0", written)
	}
	segment, _ := manager.Segment(segmentID)
	if segment.Status != Draining {
		t.Fatalf("segment status = %s, want %s so a retry can resume", segment.Status, Draining)
	}
	if segment.FramesBuffered != 4 || segment.FramesWritten != 0 {
		t.Fatalf("after canceled drain buffered=%d written=%d, want 4/0", segment.FramesBuffered, segment.FramesWritten)
	}

	written, err = manager.Drain(context.Background(), segmentID)
	if err != nil {
		t.Fatalf("resumed drain failed: %v", err)
	}
	if written != 4 {
		t.Fatalf("resumed drain wrote %d frames, want the 4 that remained buffered", written)
	}
	size, err := writer.Size(segmentID)
	if err != nil {
		t.Fatal(err)
	}
	if size <= 0 {
		t.Fatal("drained frames were not persisted to the recording file")
	}
	segment, _ = manager.Segment(segmentID)
	if segment.FramesWritten != 4 || segment.FramesBuffered != 0 {
		t.Fatalf("after resume written=%d buffered=%d, want 4/0 (no duplicate or lost frames)", segment.FramesWritten, segment.FramesBuffered)
	}
}

// Seal must refuse a recording that was never drained so buffered frames can
// never be silently dropped by closing an Open segment.
func TestSealRequiresDrainingSegment(t *testing.T) {
	manager, segmentID, _ := newDrainFixture(t)
	bufferFrames(t, manager, segmentID, 2)

	if _, err := manager.Seal(segmentID, "premature"); err == nil {
		t.Fatal("seal unexpectedly succeeded on an open segment with buffered frames")
	}
	segment, _ := manager.Segment(segmentID)
	if segment.Status != Open {
		t.Fatalf("segment status = %s, want open after rejected seal", segment.Status)
	}

	if _, err := manager.Drain(context.Background(), segmentID); err != nil {
		t.Fatal(err)
	}
	seal, err := manager.Seal(segmentID, "pass LOS complete")
	if err != nil || !seal.Complete {
		t.Fatalf("seal after drain = %#v %v, want complete", seal, err)
	}
	segment, _ = manager.Segment(segmentID)
	if segment.Status != Sealed {
		t.Fatalf("segment status = %s, want sealed", segment.Status)
	}
}
