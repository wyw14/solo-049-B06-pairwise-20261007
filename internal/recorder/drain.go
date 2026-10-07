package recorder

import (
	"context"
	"fmt"
	"time"

	"orbitlink/internal/audit"
)

// Drain flushes buffered frames to durable storage. It is resumable: if the
// context is canceled or a write fails partway through, every frame already
// appended is accounted for and the segment stays in Draining so a later call
// drains only the frames that remain buffered. No frame is appended twice.
func (m *Manager) Drain(ctx context.Context, segmentID string) (int, error) {
	m.drainMu.Lock()
	defer m.drainMu.Unlock()

	m.mu.Lock()
	current, found := m.sessions[segmentID]
	if !found {
		m.mu.Unlock()
		return 0, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if current.segment.Status != Open && current.segment.Status != Draining {
		m.mu.Unlock()
		return 0, fmt.Errorf("recording segment %s cannot drain from %s", segmentID, current.segment.Status)
	}
	current.segment.Status = Draining
	frames := append([]Frame(nil), current.buffer...)
	m.mu.Unlock()

	written := 0
	var drainErr error
	for _, frame := range frames {
		// Check cancellation before the write so a deadline never spends
		// additional frames past the recoverable point.
		if err := ctx.Err(); err != nil {
			drainErr = fmt.Errorf("recorder drain canceled after %d frames: %w", written, err)
			break
		}
		if err := m.writer.Append(segmentID, frame); err != nil {
			drainErr = err
			break
		}
		written++
	}

	m.mu.Lock()
	current, found = m.sessions[segmentID]
	if !found {
		m.mu.Unlock()
		return written, fmt.Errorf("recording segment %s vanished during drain", segmentID)
	}
	current.buffer = current.buffer[written:]
	current.segment.FramesWritten += written
	current.segment.FramesBuffered = len(current.buffer)
	if drainErr != nil {
		// Hold in Draining: flushed frames are committed, buffered frames wait
		// for a retry instead of being rewritten or lost.
		current.segment.Status = Draining
	}
	flushErr := m.flushLocked()
	m.mu.Unlock()

	if flushErr != nil {
		return written, flushErr
	}
	if drainErr != nil {
		_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "drain.interrupted", Subject: segmentID, Severity: audit.Warning, Fields: map[string]any{"frames_written": written, "frames_remaining": len(frames) - written, "error": drainErr.Error()}})
		return written, drainErr
	}
	_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "drained", Subject: segmentID, Fields: map[string]any{"frames": written}})
	return written, nil
}

// Seal closes a recording. A segment may only be sealed after it has entered
// Draining and every buffered frame has been flushed; sealing an Open segment
// would silently drop frames still held in memory.
func (m *Manager) Seal(segmentID, reason string) (SealResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, found := m.sessions[segmentID]
	if !found {
		return SealResult{}, fmt.Errorf("recording segment %s not found", segmentID)
	}
	if current.segment.Status != Draining {
		return SealResult{Segment: current.segment, Complete: false, Error: "segment must be drained before sealing"}, fmt.Errorf("recording segment %s cannot seal from %s", segmentID, current.segment.Status)
	}
	if len(current.buffer) != 0 {
		return SealResult{Segment: current.segment, Complete: false, Error: "frames remain buffered"}, fmt.Errorf("recording still has %d buffered frames", len(current.buffer))
	}
	current.segment.Status = Sealed
	current.segment.SealReason = reason
	current.segment.SealedAt = time.Now().UTC()
	if err := m.flushLocked(); err != nil {
		return SealResult{}, err
	}
	_, _ = m.audit.Record(audit.Event{Component: "recorder", Action: "sealed", Subject: segmentID, Fields: map[string]any{"frames": current.segment.FramesWritten, "reason": reason}})
	return SealResult{Segment: current.segment, Complete: true}, nil
}
