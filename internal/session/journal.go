// SPDX-License-Identifier: BSD-3-Clause
// The checkpoint (docs/design.md's restart wall): an append-only journal of the
// PFCP session messages this run applied, plus the Recovery Time Stamp it
// advertised (TS 29.244 8.2.53). A restart reads the journal before its PFCP
// socket opens and replays it, so the sessions, the SEIDs the SMF knows them by
// and the dataplane's records survive the process.
//
// Messages rather than a serialisation of the model: the messages are already
// the complete description of a session, and the code that applies them is the
// code that would have to be kept in step with any second format.
//
// A record is written *before* the SMF is answered, so every change the SMF was
// told about is in the file. That ordering is what makes a torn last line safe
// to ignore: the record that was being written belongs to a message nobody was
// answered for, and the SMF's own retransmission is what puts it back.
//
// The Recovery Time Stamp is in the file because an SMF decides by it whether
// the UP function lost its state (7.4.1). A restart that restored the journal
// re-advertises the recorded stamp -- the sessions did not go, so the SMF must
// not be told that they did -- while a restart with no usable journal
// advertises a new one and the SMF re-establishes. Advertising a new stamp
// *and* replaying sessions would be the worst of both: the SMF would consider
// every session void, re-establish them, and each establishment would be
// refused because the replayed session still holds the rule keys (compile keeps
// their owner).
package session

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The kinds of record a journal holds. The first record of a journal is always
// the Recovery Time Stamp; the rest are messages the run applied.
const (
	kindRTS       = "rts"
	kindEstablish = "establish"
	kindModify    = "modify"
	kindDelete    = "delete"
)

// journalLineLimit is how long one record's line may be: a PFCP message is
// capped at 64 KiB and the record carries it base64-encoded, so half a megabyte
// is generous. A line that long without a newline is corruption, not a record.
const journalLineLimit = 512 << 10

// journalRecord is one line of the file. The fields are exported because the
// encoding is JSON; nothing outside this file reads them.
type journalRecord struct {
	Kind  string    `json:"kind"`
	Stamp time.Time `json:"stamp,omitempty"`
	SEID  uint64    `json:"seid,omitempty"`
	Msg   []byte    `json:"msg,omitempty"`
}

// Journal is the checkpoint file, open for appending.
type Journal struct {
	path string

	mu    sync.Mutex
	f     *os.File
	stamp time.Time
	// hasStamp is whether the journal carries the Recovery Time Stamp of the
	// run that created it, and broken is whether a record failed to be written:
	// a journal that could not record what was applied does not describe the
	// sessions any more, so a restart must not claim continuity from it.
	hasStamp bool
	broken   bool
}

// OpenJournal opens the checkpoint at path, creating the file when it is not
// there, and reads what it holds. A file that cannot be read as a journal is an
// error: the caller decides between a clean slate and an outage, and this layer
// will not guess.
func OpenJournal(path string) (*Journal, error) {
	j := &Journal{path: path}
	recs, err := readJournal(path)
	if err != nil {
		return nil, err
	}
	if len(recs) > 0 && recs[0].Kind == kindRTS {
		j.stamp, j.hasStamp = recs[0].Stamp, true
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("checkpoint %s: %w", path, err)
	}
	j.f = f
	return j, nil
}

// Recovery is the Recovery Time Stamp the previous run advertised, and whether
// the journal carries one. A journal with no stamp -- a new file, an empty one,
// or one whose first record is not the stamp -- has nothing to preserve, so the
// caller advertises a new stamp and the SMF re-establishes; so has a journal
// whose records stopped being written, because it no longer describes what was
// applied.
func (j *Journal) Recovery() (time.Time, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.broken {
		return time.Time{}, false
	}
	return j.stamp, j.hasStamp
}

// Start records the Recovery Time Stamp this run advertises. A run that
// restored its sessions passes the stamp they were created under and the
// journal's own record is left alone -- continuity is the point. A run that
// restored nothing has no sessions to preserve, so the file is rewritten to
// begin with the stamp this run advertises: a later restart must not read a
// stamp no run ever advertised, and a stamp that moves *backwards* is worse
// than one that moves forwards (7.4.1 reads the move as a restart, and nothing
// defines a stamp older than its predecessor).
func (j *Journal) Start(stamp time.Time, restored bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if restored && j.hasStamp && !j.broken {
		return nil
	}
	// Truncate, not append: any records the file held describe sessions this
	// run did not restore, and the stamp has to come first for a later restart
	// to read the file as a checkpoint at all.
	if err := j.f.Truncate(0); err != nil {
		j.broken = true
		return fmt.Errorf("checkpoint %s: %w", j.path, err)
	}
	j.stamp, j.hasStamp, j.broken = stamp, false, false
	if err := j.appendLocked(journalRecord{Kind: kindRTS, Stamp: stamp}); err != nil {
		j.broken = true
		return err
	}
	j.hasStamp = true
	return nil
}

// Reset forgets every session record and keeps the Recovery Time Stamp: the
// sessions the journal described are void (the association ended, so the SMF
// will re-establish them), and a later restart must not replay them. The file
// is truncated rather than appended to, so it does not grow with this event.
func (j *Journal) Reset() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.f.Truncate(0); err != nil {
		j.broken = true
		return fmt.Errorf("checkpoint %s: %w", j.path, err)
	}
	if !j.hasStamp || j.broken {
		return nil
	}
	if err := j.appendLocked(journalRecord{Kind: kindRTS, Stamp: j.stamp}); err != nil {
		j.broken = true
		return err
	}
	return nil
}

// Close closes the file.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return nil
	}
	return j.f.Close()
}

// record appends one applied message, before the SMF is answered. A failure is
// an error to report, not a reason to refuse the session: the change is in the
// dataplane, and what the caller can still do is stop pretending the journal
// describes it (Recovery says so afterwards, so the next restart advertises a
// new Recovery Time Stamp and the SMF re-establishes).
func (j *Journal) record(kind string, seid uint64, msg message.Message) error {
	// A message is marshalled through the interface it arrives as: MarshalTo is
	// the interface's own writer, and message.Parse is its reader, so a record
	// is the bytes the SMF sent (header and all) rather than a shape of our own.
	raw := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(raw); err != nil {
		return fmt.Errorf("checkpoint %s: marshalling a %s: %w", j.path, kind, err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.broken {
		return nil
	}
	if err := j.appendLocked(journalRecord{Kind: kind, SEID: seid, Msg: raw}); err != nil {
		j.broken = true
		return err
	}
	return nil
}

// appendLocked writes one record and makes it durable. The durability is the
// point: the SMF was told the change was applied, so it has to survive the
// machine, not just this process. The caller holds the lock.
func (j *Journal) appendLocked(rec journalRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := j.f.Write(b); err != nil {
		return fmt.Errorf("checkpoint %s: %w", j.path, err)
	}
	if err := j.f.Sync(); err != nil {
		return fmt.Errorf("checkpoint %s: %w", j.path, err)
	}
	return nil
}

// readJournal reads the records a journal file holds, in order. A last line
// without a newline is the record that was being written when the previous run
// died: the record is written before the answer, so the message it describes
// was never answered and does not belong to the checkpoint. A line longer than
// journalLineLimit, or a line that does not parse, is corruption and an error:
// a caller that cannot trust the file must not replay half of it.
func readJournal(path string) ([]journalRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("checkpoint %s: %w", path, err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 64<<10)
	var recs []journalRecord
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > journalLineLimit {
			return nil, fmt.Errorf("checkpoint %s: a record is longer than %d bytes", path, journalLineLimit)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("checkpoint %s: %w", path, err)
		}
		if len(line) == 0 || line[len(line)-1] != '\n' {
			// The torn tail, or the end of a complete file.
			return recs, nil
		}
		var rec journalRecord
		if err := json.Unmarshal(bytes.TrimSuffix(line, []byte("\n")), &rec); err != nil {
			return nil, fmt.Errorf("checkpoint %s: %w", path, err)
		}
		recs = append(recs, rec)
	}
}

// Restore replays a journal into a compiler that holds nothing: the sessions
// the previous run applied come back, each under the local SEID the SMF knows
// it by. The caller does this before the PFCP socket opens (and after the
// sweep, so the dataplane's records are the ones the replay writes rather than
// an earlier run's).
//
// A message the replay refuses is not a reason to stop: the model is the
// journal's and the SMF's own retransmissions are what reconcile the two, which
// is the same contract a refused modification has with a live session. The
// error return is for a journal this layer cannot read -- an unparseable
// message -- and the caller's answer to that is to treat the checkpoint as
// unusable, not to keep half of it.
func (c *Compiler) Restore(j *Journal) error {
	recs, err := readJournal(j.path)
	if err != nil {
		return err
	}
	if len(recs) == 0 || recs[0].Kind != kindRTS {
		// No stamp means no checkpoint: an empty journal, or one whose first
		// record is not the stamp. The caller advertises a new stamp and the
		// SMF re-establishes; replaying sessions would strand them.
		return nil
	}
	// A replay is not an apply: the records are already in the file, and
	// appending them back would double it on every restart. No request is in
	// flight while this runs (the socket opens after), so the pointer needs no
	// lock.
	c.restoring = true
	defer func() { c.restoring = false }()
	applied := 0
	for _, rec := range recs[1:] {
		msg, err := message.Parse(rec.Msg)
		if err != nil {
			return fmt.Errorf("checkpoint %s: %w", j.path, err)
		}
		var resp message.Message
		switch m := msg.(type) {
		case *message.SessionEstablishmentRequest:
			// The session's local SEID is the one the SMF's later messages
			// carry, so the replay pins the allocator to it rather than taking
			// the next value.
			if rec.SEID != 0 {
				c.mu.Lock()
				c.nextSEID = rec.SEID
				c.mu.Unlock()
			}
			resp = c.establish(m)
		case *message.SessionModificationRequest:
			resp = c.modify(m)
		case *message.SessionDeletionRequest:
			resp = c.delete(m)
		default:
			return fmt.Errorf("checkpoint %s: a %q record is not a session message", j.path, rec.Kind)
		}
		if got := answerCause(resp); got != ie.CauseRequestAccepted && got != ie.CauseSessionContextNotFound {
			c.log.Warn("session: a replayed message was refused",
				"kind", rec.Kind, "seid", rec.SEID, "cause", got)
			continue
		}
		applied++
	}
	c.log.Info("session: checkpoint replayed", "path", j.path, "messages", applied,
		"sessions", c.Stats().Sessions)
	return nil
}
