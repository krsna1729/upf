// SPDX-License-Identifier: BSD-3-Clause
// The checkpoint (docs/design.md's restart wall): a journal of the PFCP session
// messages this run applied, plus the Recovery Time Stamp it advertised (TS
// 29.244 8.2.53). A restart reads the journal before its PFCP socket opens and
// replays it, so the sessions, the SEIDs the SMF knows them by and the
// dataplane's records survive the process.
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
// The file holds the sessions, not their history. Records are appended as the
// messages are applied, and once they number more than twice the sessions they
// leave standing the file is compacted: rewritten as one establishment per live
// session with every later modification folded in (foldModification), and
// renamed over the old one. A restart reads the same fold, so it replays one
// establishment per session however many messages the session took.
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
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
// encoding is JSON; nothing outside this file reads them. On the stamp record
// SEID is the local SEID the next session may take: a compacted journal no
// longer names the SEIDs of the sessions it dropped, and a restart must not
// hand one of them to a new session that a late retransmission could address.
type journalRecord struct {
	Kind  string    `json:"kind"`
	Stamp time.Time `json:"stamp,omitempty"`
	SEID  uint64    `json:"seid,omitempty"`
	Msg   []byte    `json:"msg,omitempty"`
}

// journalFile is what a journal writes through: the *os.File, or a test's.
type journalFile interface {
	io.Writer
	Sync() error
	Truncate(size int64) error
	Close() error
}

// Journal is the checkpoint file, open for appending.
type Journal struct {
	path string

	// flush serialises the fsyncs (syncTo), and flushed is how many records
	// they have made durable. It is taken before mu, never after.
	flush   sync.Mutex
	flushed uint64

	mu    sync.Mutex
	f     journalFile
	log   *slog.Logger
	stamp time.Time
	// hasStamp is whether the journal carries the Recovery Time Stamp of the
	// run that created it, and broken is whether a record failed to be written:
	// a journal that could not record what was applied does not describe the
	// sessions any more, so a restart must not claim continuity from it.
	hasStamp bool
	broken   bool
	// size is the bytes in the file, and written the records ever written to
	// it: the count the fsyncs are measured in.
	size    int64
	written uint64
	// records is the session records the file holds and live the sessions
	// they leave standing; a file with more than twice as many records as
	// sessions is compacted. compacting says a compaction is running,
	// compactAt is the record count a retry waits for after one failed, and
	// gen moves whenever Start or Reset rewrites the file, so a compaction of
	// the file as it was does not replace it.
	records, live int
	compactAt     int
	compacting    bool
	gen           uint64
	compactions   sync.WaitGroup
}

// OpenJournal opens the checkpoint at path, creating the file when it is not
// there, and reads its stamp. Only the first record is read: the sessions are
// Restore's to read, and a run that restores nothing never needs them. A first
// record that cannot be read is an error: the caller decides between a clean
// slate and an outage, and this layer will not guess.
func OpenJournal(path string) (*Journal, error) {
	j := &Journal{path: path}
	err := eachRecord(path, -1, func(rec journalRecord, _ int64) error {
		if rec.Kind == kindRTS {
			j.stamp, j.hasStamp = rec.Stamp, true
		}
		return errEnough
	})
	if err != nil && !errors.Is(err, errEnough) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("checkpoint %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("checkpoint %s: %w", path, err)
	}
	j.f, j.size = f, info.Size()
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
	if err := j.truncateLocked(); err != nil {
		j.broken = true
		return err
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
	if err := j.truncateLocked(); err != nil {
		j.broken = true
		return err
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

// truncateLocked empties the file, and with it the counts and any compaction
// of what the file held. The caller holds the lock.
func (j *Journal) truncateLocked() error {
	if err := j.f.Truncate(0); err != nil {
		return fmt.Errorf("checkpoint %s: %w", j.path, err)
	}
	j.gen++
	j.size, j.records, j.live, j.compactAt = 0, 0, 0, 0
	return nil
}

// Close closes the file, once a compaction that is running has finished.
func (j *Journal) Close() error {
	j.compactions.Wait()
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
	if j.broken {
		j.mu.Unlock()
		return nil
	}
	if err := j.writeLocked(journalRecord{Kind: kind, SEID: seid, Msg: raw}); err != nil {
		j.broken = true
		j.mu.Unlock()
		return err
	}
	seq := j.written
	j.records++
	switch kind {
	case kindEstablish:
		j.live++
	case kindDelete:
		j.live--
	}
	if j.hasStamp && !j.compacting && j.records > 2*j.live && j.records >= j.compactAt {
		j.compacting = true
		j.compactions.Add(1)
		go j.compact()
	}
	j.mu.Unlock()
	return j.syncTo(seq)
}

// writeLocked writes one record. The caller holds the lock.
func (j *Journal) writeLocked(rec journalRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	n, err := j.f.Write(b)
	j.size += int64(n)
	if err != nil {
		return fmt.Errorf("checkpoint %s: %w", j.path, err)
	}
	j.written++
	return nil
}

// appendLocked writes one record and makes it durable. The durability is the
// point: the SMF was told the change was applied, so it has to survive the
// machine, not just this process. The caller holds the lock.
func (j *Journal) appendLocked(rec journalRecord) error {
	if err := j.writeLocked(rec); err != nil {
		return err
	}
	if err := j.f.Sync(); err != nil {
		return fmt.Errorf("checkpoint %s: %w", j.path, err)
	}
	return nil
}

// syncTo makes the records up to the seq-th durable. The fsyncs are a group
// commit: whoever syncs takes everything written so far with it, and a record
// an earlier sync already covered returns without one of its own -- so the
// session messages share the disk's latency instead of queueing one fsync each
// behind the lock their writes take.
func (j *Journal) syncTo(seq uint64) error {
	j.flush.Lock()
	defer j.flush.Unlock()
	if j.flushed >= seq {
		return nil
	}
	j.mu.Lock()
	f, upTo := j.f, j.written
	j.mu.Unlock()
	if err := f.Sync(); err != nil {
		j.mu.Lock()
		j.broken = true
		j.mu.Unlock()
		return fmt.Errorf("checkpoint %s: %w", j.path, err)
	}
	j.flushed = upTo
	return nil
}

// compact rewrites the journal as the sessions its records leave standing. It
// runs beside the session messages: the fold reads the file as it stood when
// the compaction began, the records written since are carried over as they
// are, and the new file is renamed over the old one, so a crash leaves one
// whole journal or the other. It goes round again while the file is still
// due, so a journal that stops taking messages is left compacted.
func (j *Journal) compact() {
	defer j.compactions.Done()
	for {
		again, err := j.compactOnce()
		if err != nil {
			j.mu.Lock()
			log := j.log
			j.mu.Unlock()
			if log != nil {
				log.Warn("session: could not compact the checkpoint", "path", j.path, "error", err)
			}
		}
		if !again {
			return
		}
	}
}

// compactOnce is one compaction, and whether the file is due another. Every
// return leaves j.compacting as the answer says.
func (j *Journal) compactOnce() (bool, error) {
	j.mu.Lock()
	gen, size, records, live := j.gen, j.size, j.records, j.live
	j.mu.Unlock()
	// A failure leaves the journal as it was, which is still whole; the retry
	// waits for it to double, so a disk that refuses the copy is not asked
	// again on every message.
	fail := func(out *os.File, err error) (bool, error) {
		if out != nil {
			out.Close()
			os.Remove(out.Name())
		}
		if j.gen == gen {
			j.compactAt = 2 * j.records
		} else {
			err = nil // Start or Reset replaced what was being read
		}
		j.compacting = false
		return false, err
	}

	fold, err := foldJournal(j.path, size)
	if err == nil && !fold.hasStamp {
		err = errors.New("no Recovery Time Stamp")
	}
	var out *os.File
	if err == nil {
		out, err = os.OpenFile(j.path+".compact", os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_APPEND, 0o600)
	}
	var n int64
	if err == nil {
		if n, err = writeFold(out, fold); err == nil {
			err = out.Sync()
		}
	}
	if err != nil {
		j.mu.Lock()
		defer j.mu.Unlock()
		return fail(out, fmt.Errorf("checkpoint %s: compacting: %w", j.path, err))
	}

	j.flush.Lock()
	defer j.flush.Unlock()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.gen != gen || j.broken {
		return fail(out, nil)
	}
	// The records written since the fold read the file go over as they are.
	tail, err := copyTail(out, j.path, size, j.size-size)
	if err == nil {
		err = out.Sync()
	}
	if err == nil {
		err = os.Rename(out.Name(), j.path)
	}
	if err != nil {
		return fail(out, fmt.Errorf("checkpoint %s: compacting: %w", j.path, err))
	}
	j.f.Close()
	j.f = out
	j.size = n + tail
	j.records += len(fold.sessions) - records
	j.live += len(fold.sessions) - live
	j.flushed = j.written // the new file was synced whole
	j.compactAt = 0
	j.compacting = j.records > 2*j.live
	// The rename is durable once the directory is: until then a crash finds
	// the old file, which holds every record too.
	if err := syncDir(j.path); err != nil {
		return j.compacting, fmt.Errorf("checkpoint %s: compacting: %w", j.path, err)
	}
	return j.compacting, nil
}

// copyTail appends the n bytes of the file at path from offset off to out.
func copyTail(out io.Writer, path string, off, n int64) (int64, error) {
	src, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	return io.Copy(out, io.NewSectionReader(src, off, n))
}

func syncDir(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// writeFold writes a fold as a journal: the stamp, then one establishment per
// live session in the order they were established.
func writeFold(out io.Writer, fold *journalFold) (int64, error) {
	w := bufio.NewWriterSize(out, 64<<10)
	var n int64
	put := func(rec journalRecord) error {
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		m, err := w.Write(append(b, '\n'))
		n += int64(m)
		return err
	}
	if err := put(journalRecord{Kind: kindRTS, Stamp: fold.stamp, SEID: fold.next}); err != nil {
		return n, err
	}
	for _, s := range fold.inOrder() {
		if err := put(journalRecord{Kind: kindEstablish, SEID: s.seid, Msg: s.msg}); err != nil {
			return n, err
		}
	}
	return n, w.Flush()
}

// errEnough stops eachRecord before the end of the file.
var errEnough = errors.New("enough records")

// eachRecord hands fn the records of a journal file in order, with the offset
// each one's line ends at, reading at most limit bytes (all of them when limit
// is negative). A last line without a newline is the record that was being
// written when the previous run died: the record is written before the
// answer, so the message it describes was never answered and does not belong
// to the checkpoint. A line longer than journalLineLimit, or a line that does
// not parse, is corruption and an error: a caller that cannot trust the file
// must not replay half of it.
func eachRecord(path string, limit int64, fn func(rec journalRecord, end int64) error) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("checkpoint %s: %w", path, err)
	}
	defer f.Close()

	var src io.Reader = f
	if limit >= 0 {
		src = io.LimitReader(f, limit)
	}
	r := bufio.NewReaderSize(src, 64<<10)
	var end int64
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > journalLineLimit {
			return fmt.Errorf("checkpoint %s: a record is longer than %d bytes", path, journalLineLimit)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("checkpoint %s: %w", path, err)
		}
		if len(line) == 0 || line[len(line)-1] != '\n' {
			// The torn tail, or the end of a complete file.
			return nil
		}
		end += int64(len(line))
		var rec journalRecord
		if err := json.Unmarshal(bytes.TrimSuffix(line, []byte("\n")), &rec); err != nil {
			return fmt.Errorf("checkpoint %s: %w", path, err)
		}
		if err := fn(rec, end); err != nil {
			return err
		}
	}
}

// journalFold is what a journal's records leave standing: the stamp, and per
// live session the establishment that, with every later modification folded
// in, describes it.
type journalFold struct {
	stamp    time.Time
	hasStamp bool
	// next is above every local SEID the journal named.
	next uint64
	// records is the session records read, and size the bytes of complete
	// records: a torn last line is past it.
	records  int
	size     int64
	sessions map[uint64]*foldedSession
}

type foldedSession struct {
	seid uint64
	at   int // the establishment's place among the records: the replay keeps the order
	msg  []byte
}

// inOrder is the live sessions in the order they were established.
func (f *journalFold) inOrder() []*foldedSession {
	out := make([]*foldedSession, 0, len(f.sessions))
	for _, s := range f.sessions {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b *foldedSession) int { return cmp.Compare(a.at, b.at) })
	return out
}

// foldJournal reads the first limit bytes of the journal at path (all of it
// when limit is negative) into the sessions they leave standing. The fold
// holds a session's establishment as bytes, so it costs what the live sessions'
// records do, not what their history did. A journal whose first record is not
// the stamp is no checkpoint, and nothing past it is read.
func foldJournal(path string, limit int64) (*journalFold, error) {
	fold := &journalFold{sessions: map[uint64]*foldedSession{}}
	err := eachRecord(path, limit, func(rec journalRecord, end int64) error {
		if !fold.hasStamp {
			if rec.Kind != kindRTS {
				return errEnough
			}
			fold.stamp, fold.hasStamp, fold.next, fold.size = rec.Stamp, true, rec.SEID, end
			return nil
		}
		fold.records++
		fold.size = end
		msg, err := message.Parse(rec.Msg)
		if err != nil {
			return fmt.Errorf("checkpoint %s: %w", path, err)
		}
		switch m := msg.(type) {
		case *message.SessionEstablishmentRequest:
			fold.sessions[rec.SEID] = &foldedSession{seid: rec.SEID, at: fold.records, msg: rec.Msg}
			fold.next = max(fold.next, rec.SEID+1)
		case *message.SessionModificationRequest:
			s := fold.sessions[rec.SEID]
			if s == nil {
				return nil
			}
			est, err := message.ParseSessionEstablishmentRequest(s.msg)
			if err != nil {
				return fmt.Errorf("checkpoint %s: %w", path, err)
			}
			foldModification(est, m)
			if s.msg, err = est.Marshal(); err != nil {
				return fmt.Errorf("checkpoint %s: %w", path, err)
			}
		case *message.SessionDeletionRequest:
			delete(fold.sessions, rec.SEID)
		default:
			return fmt.Errorf("checkpoint %s: a %q record is not a session message", path, rec.Kind)
		}
		return nil
	})
	if err != nil && !errors.Is(err, errEnough) {
		return nil, err
	}
	return fold, nil
}

// foldModification folds a modification into the establishment that describes
// its session, so the establishment alone replays into the model the two
// messages build. It is merge's fold (compile.go) on the messages rather than
// the model: the same order -- the QERs, FARs, MARs, BARs and URRs a message
// creates or updates, then the PDRs, FARs and BARs it removes, then its PDRs,
// then the MARs, QERs and URRs it removes -- and the same rule per field: a
// field an update names replaces the one before it, a repeated one (a Linked
// URR ID) replaces the list, and what it leaves out stays. The exceptions are
// merge's own: an Update PDR is the PDR's whole new form but for an F-TEID it
// leaves out; a QER's gates are set by every message, open where it names none;
// a zero Averaging Window and a placeholder Outer Header Creation name nothing.
// What only the message itself acts on (SNDEM, DROBU, Query URR) is not state
// and is not kept.
func foldModification(est *message.SessionEstablishmentRequest, mod *message.SessionModificationRequest) {
	for _, q := range slices.Concat(mod.CreateQER, mod.UpdateQER) {
		est.CreateQER = foldRule(est.CreateQER, ie.CreateQER, ie.QERID, q, foldQER)
	}
	for _, f := range slices.Concat(mod.CreateFAR, mod.UpdateFAR) {
		est.CreateFAR = foldRule(est.CreateFAR, ie.CreateFAR, ie.FARID, f, foldFAR)
	}
	for _, m := range slices.Concat(mod.CreateMAR, mod.UpdateMAR) {
		est.CreateMAR = foldRule(est.CreateMAR, ie.CreateMAR, ie.MARID, m, foldMAR)
	}
	// An establishment carries one Create BAR (Table 7.5.2.1-1): a session an
	// SMF gave a second one keeps the last.
	var bars []*ie.IE
	if est.CreateBAR != nil {
		bars = append(bars, est.CreateBAR)
	}
	for _, b := range []*ie.IE{mod.CreateBAR, mod.UpdateBAR} {
		if b != nil {
			bars = foldRule(bars, ie.CreateBAR, ie.BARID, b, foldFields)
		}
	}
	for _, u := range slices.Concat(mod.CreateURR, mod.UpdateURR) {
		est.CreateURR = foldRule(est.CreateURR, ie.CreateURR, ie.URRID, u, foldFields)
	}

	est.CreatePDR = removeRules(est.CreatePDR, ie.PDRID, mod.RemovePDR, nil)
	est.CreateFAR = removeRules(est.CreateFAR, ie.FARID, mod.RemoveFAR, nil)
	if mod.RemoveBAR != nil {
		if id := childOf(mod.RemoveBAR.ChildIEs, ie.BARID); id != nil {
			bars = removeRules(bars, ie.BARID, []*ie.IE{mod.RemoveBAR}, nil)
			// A FAR that buffered under the BAR stops naming it (merge).
			for n, f := range est.CreateFAR {
				if b := childOf(f.ChildIEs, ie.BARID); b != nil && bytes.Equal(b.Payload, id.Payload) {
					est.CreateFAR[n] = ie.NewGroupedIE(ie.CreateFAR, withoutType(f.ChildIEs, ie.BARID)...)
				}
			}
		}
	}
	est.CreateBAR = nil
	if len(bars) > 0 {
		est.CreateBAR = bars[len(bars)-1]
	}

	for _, p := range slices.Concat(mod.CreatePDR, mod.UpdatePDR) {
		est.CreatePDR = foldRule(est.CreatePDR, ie.CreatePDR, ie.PDRID, p, foldPDR)
	}

	est.CreateMAR = removeRules(est.CreateMAR, ie.MARID, mod.RemoveMAR, nil)
	// A QER the message also brings is a replacement, not a removal (merge).
	est.CreateQER = removeRules(est.CreateQER, ie.QERID, mod.RemoveQER, slices.Concat(mod.CreateQER, mod.UpdateQER))
	est.CreateURR = removeRules(est.CreateURR, ie.URRID, mod.RemoveURR, nil)
}

// foldRule folds one Create or Update IE into a session's Create IEs of its
// kind: merged into the rule with the same id, or added as a new one.
func foldRule(rules []*ie.IE, create, id ie.IEType, in *ie.IE, fold func(had []*ie.IE, in *ie.IE) []*ie.IE) []*ie.IE {
	key := childOf(in.ChildIEs, id)
	if key == nil {
		return rules // refused by the parse, so never journalled
	}
	for n, r := range rules {
		if k := childOf(r.ChildIEs, id); k != nil && bytes.Equal(k.Payload, key.Payload) {
			rules[n] = ie.NewGroupedIE(create, fold(r.ChildIEs, in)...)
			return rules
		}
	}
	return append(rules, ie.NewGroupedIE(create, fold(nil, in)...))
}

// removeRules drops the rules the Remove IEs name, except the ones kept names.
func removeRules(rules []*ie.IE, id ie.IEType, removes, kept []*ie.IE) []*ie.IE {
	named := func(list []*ie.IE, key *ie.IE) bool {
		return slices.ContainsFunc(list, func(r *ie.IE) bool {
			k := childOf(r.ChildIEs, id)
			return k != nil && bytes.Equal(k.Payload, key.Payload)
		})
	}
	for _, rm := range removes {
		key := childOf(rm.ChildIEs, id)
		if key == nil || named(kept, key) {
			continue
		}
		rules = slices.DeleteFunc(rules, func(r *ie.IE) bool { return named([]*ie.IE{r}, key) })
	}
	return rules
}

// childOf is the first child of type t, or nil.
func childOf(children []*ie.IE, t ie.IEType) *ie.IE {
	for _, c := range children {
		if c.Type == t {
			return c
		}
	}
	return nil
}

// withoutType is children less those of type t.
func withoutType(children []*ie.IE, t ie.IEType) []*ie.IE {
	return slices.DeleteFunc(slices.Clone(children), func(c *ie.IE) bool { return c.Type == t })
}

// withFields is had with every child type update names replaced by update's
// children of that type.
func withFields(had, update []*ie.IE) []*ie.IE {
	out := make([]*ie.IE, 0, len(had)+len(update))
	for _, c := range had {
		if childOf(update, c.Type) == nil {
			out = append(out, c)
		}
	}
	return append(out, update...)
}

// foldFields is the plain rule (a URR, a BAR): the fields an update names
// replace the ones before them.
func foldFields(had []*ie.IE, in *ie.IE) []*ie.IE { return withFields(had, in.ChildIEs) }

// foldPDR: an update is the PDR's whole new form, but an F-TEID it leaves out
// keeps the tunnel the PDR has.
func foldPDR(had []*ie.IE, in *ie.IE) []*ie.IE {
	out := slices.Clone(in.ChildIEs)
	var fteid *ie.IE
	if pdi := childOf(had, ie.PDI); pdi != nil {
		fteid = childOf(pdi.ChildIEs, ie.FTEID)
	}
	if fteid == nil {
		return out
	}
	var pdi []*ie.IE
	if p := childOf(out, ie.PDI); p != nil {
		if childOf(p.ChildIEs, ie.FTEID) != nil {
			return out
		}
		pdi = p.ChildIEs
	}
	return withFields(out, []*ie.IE{ie.NewGroupedIE(ie.PDI, append(slices.Clone(pdi), fteid)...)})
}

// foldFAR: the fields an update names replace the ones before them, and so do
// the forwarding parameters it names, one by one.
func foldFAR(had []*ie.IE, in *ie.IE) []*ie.IE {
	var fields, fwd []*ie.IE
	named := false
	for _, c := range in.ChildIEs {
		if c.Type != ie.ForwardingParameters && c.Type != ie.UpdateForwardingParameters {
			fields = append(fields, c)
			continue
		}
		named = true
		for _, p := range c.ChildIEs {
			if p.Type == ie.PFCPSMReqFlags || placeholderTunnel(p) {
				continue
			}
			fwd = append(fwd, p)
		}
	}
	out := withFields(had, fields)
	if !named {
		return out
	}
	var params []*ie.IE
	if p := childOf(had, ie.ForwardingParameters); p != nil {
		params = p.ChildIEs
	}
	return withFields(out, []*ie.IE{ie.NewGroupedIE(ie.ForwardingParameters, withFields(params, fwd)...)})
}

// placeholderTunnel is an Outer Header Creation with TEID 0 and the
// unspecified address: no tunnel yet (parseForwardingParameters).
func placeholderTunnel(c *ie.IE) bool {
	if c.Type != ie.OuterHeaderCreation {
		return false
	}
	f, err := c.OuterHeaderCreation()
	if err != nil || f.TEID != 0 {
		return false
	}
	addr, ok := netip.AddrFromSlice(f.IPv4Address)
	if !ok {
		addr, ok = netip.AddrFromSlice(f.IPv6Address)
	}
	return ok && addr.Unmap().IsUnspecified()
}

// foldQER: the fields an update names replace the ones before them, but the
// gates are set by every message, open where it names none, and a zero
// Averaging Window is no window.
func foldQER(had []*ie.IE, in *ie.IE) []*ie.IE {
	fields := slices.DeleteFunc(slices.Clone(in.ChildIEs), func(c *ie.IE) bool {
		if c.Type != ie.AveragingWindow {
			return false
		}
		v, err := c.AveragingWindow()
		return err != nil || v == 0
	})
	out := withFields(had, fields)
	if childOf(fields, ie.GateStatus) == nil {
		out = withoutType(out, ie.GateStatus)
	}
	return out
}

// foldMAR: the fields an update names replace the ones before them. An
// access a Create MAR names, or an Update MAR names in the create form, is
// replaced whole; one an Update MAR names in the update form has its fields
// replaced, and a null-length one is deregistered.
func foldMAR(had []*ie.IE, in *ie.IE) []*ie.IE {
	var fields []*ie.IE
	out := had
	for _, c := range in.ChildIEs {
		access, partial := c.Type, false
		switch c.Type {
		case ie.UpdateTGPPAccessForwardingActionInformation:
			access, partial = ie.TGPPAccessForwardingActionInformation, in.Type == ie.UpdateMAR
		case ie.UpdateNonTGPPAccessForwardingActionInformation:
			access, partial = ie.NonTGPPAccessForwardingActionInformation, in.Type == ie.UpdateMAR
		case ie.TGPPAccessForwardingActionInformation, ie.NonTGPPAccessForwardingActionInformation:
		default:
			fields = append(fields, c)
			continue
		}
		var accessFields []*ie.IE
		if partial {
			if len(c.ChildIEs) == 0 {
				out = withoutType(out, access)
				continue
			}
			if a := childOf(out, access); a != nil {
				accessFields = a.ChildIEs
			}
		}
		out = withFields(out, []*ie.IE{ie.NewGroupedIE(access, withFields(accessFields, c.ChildIEs)...)})
	}
	return withFields(out, fields)
}

// Restore replays a journal into a compiler that holds nothing: the sessions
// the previous run applied come back, each under the local SEID the SMF knows
// it by. The caller does this before the PFCP socket opens (and after the
// sweep, so the dataplane's records are the ones the replay writes rather than
// an earlier run's). The journal is read once, as the fold a compaction writes
// (foldJournal), so the replay is one establishment per live session: what the
// sessions are, not every message that made them.
//
// A session the replay refuses is not a reason to stop: the model is the
// journal's and the SMF's own retransmissions are what reconcile the two, which
// is the same contract a refused modification has with a live session. The
// error return is for a journal this layer cannot read -- an unparseable
// message -- and the caller's answer to that is to treat the checkpoint as
// unusable, not to keep half of it.
func (c *Compiler) Restore(j *Journal) error {
	fold, err := foldJournal(j.path, -1)
	if err != nil {
		return err
	}
	if !fold.hasStamp {
		// No stamp means no checkpoint: an empty journal, or one whose first
		// record is not the stamp. The caller advertises a new stamp and the
		// SMF re-establishes; replaying sessions would strand them.
		return nil
	}
	if err := j.restored(fold); err != nil {
		return err
	}
	// A replay is not an apply: the records are already in the file, and
	// appending them back would double it on every restart. No request is in
	// flight while this runs (the socket opens after), so the pointer needs no
	// lock.
	c.restoring = true
	defer func() { c.restoring = false }()
	applied := 0
	for _, s := range fold.inOrder() {
		req, err := message.ParseSessionEstablishmentRequest(s.msg)
		if err != nil {
			return fmt.Errorf("checkpoint %s: %w", j.path, err)
		}
		// The session's local SEID is the one the SMF's later messages carry,
		// so the replay pins the allocator to it rather than taking the next
		// value.
		if s.seid != 0 {
			c.mu.Lock()
			c.nextSEID = s.seid
			c.mu.Unlock()
		}
		if got := answerCause(c.establish(req)); got != ie.CauseRequestAccepted {
			c.log.Warn("session: a replayed session was refused", "seid", s.seid, "cause", got)
			continue
		}
		applied++
	}
	// And past every SEID the journal named, the deleted sessions' included.
	c.mu.Lock()
	c.nextSEID = max(c.nextSEID, fold.next)
	c.mu.Unlock()
	c.log.Info("session: checkpoint replayed", "path", j.path, "records", fold.records,
		"messages", applied, "sessions", c.Stats().Sessions)
	return nil
}

// restored takes the counts a replay read, which the next compaction measures
// from, and cuts a torn last record off the file: the next record would
// otherwise be written onto the end of it, and the line the two made would be
// corruption to every later read.
func (j *Journal) restored(fold *journalFold) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.records, j.live = fold.records, len(fold.sessions)
	if fold.size < j.size {
		if err := j.f.Truncate(fold.size); err != nil {
			return fmt.Errorf("checkpoint %s: %w", j.path, err)
		}
		j.size = fold.size
	}
	return nil
}
