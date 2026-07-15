// Package postfixq wraps Postfix queue management via postqueue(1)/postsuper(1)
// through internal/sys. Queue ids are validated (^[A-F0-9]{6,16}$) before use.
package postfixq

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

// Binary paths (absolute; matches the old system).
const (
	binPostqueue = "/usr/sbin/postqueue"
	binPostsuper = "/usr/sbin/postsuper"
)

// ErrNotFound is returned by Show when no queued mail has the given queue id.
var ErrNotFound = errors.New("postfixq: queue id not found")

// Mail is one queued message.
type Mail struct {
	QueueID string   `json:"queue_id"`
	Size    int64    `json:"size"`
	Arrival string   `json:"arrival"`
	Sender  string   `json:"sender"`
	Rcpts   []string `json:"recipients"`
	Status  string   `json:"status"`
	Reason  string   `json:"reason,omitempty"`
}

// Service runs postqueue/postsuper.
type Service struct {
	runner *sys.Runner
}

// New builds a Service.
func New(runner *sys.Runner) *Service { return &Service{runner: runner} }

// List returns all queued mails (parsed from `postqueue -j`).
func (s *Service) List(ctx context.Context) ([]Mail, error) {
	out, err := s.runner.Output(ctx, binPostqueue, "-j")
	if err != nil {
		return nil, fmt.Errorf("postfixq.List: %w", err)
	}
	mails, err := parseQueueJSON([]byte(out))
	if err != nil {
		return nil, fmt.Errorf("postfixq.List: %w", err)
	}
	return mails, nil
}

// Show returns one queued mail by validated queue id.
func (s *Service) Show(ctx context.Context, qid string) (Mail, error) {
	qid, err := valid.QueueID(qid)
	if err != nil {
		return Mail{}, fmt.Errorf("postfixq.Show: %w", err)
	}
	mails, err := s.List(ctx)
	if err != nil {
		return Mail{}, fmt.Errorf("postfixq.Show: %w", err)
	}
	for _, m := range mails {
		if m.QueueID == qid {
			return m, nil
		}
	}
	return Mail{}, fmt.Errorf("postfixq.Show %s: %w", qid, ErrNotFound)
}

// Flush attempts delivery of the entire deferred queue.
func (s *Service) Flush(ctx context.Context) error {
	if _, err := s.runner.Output(ctx, binPostqueue, "-f"); err != nil {
		return fmt.Errorf("postfixq.Flush: %w", err)
	}
	return nil
}

// Hold places a message on hold.
func (s *Service) Hold(ctx context.Context, qid string) error {
	return s.postsuper(ctx, "Hold", "-h", qid)
}

// Release releases a held message.
func (s *Service) Release(ctx context.Context, qid string) error {
	return s.postsuper(ctx, "Release", "-H", qid)
}

// Delete removes a message from the queue.
func (s *Service) Delete(ctx context.Context, qid string) error {
	return s.postsuper(ctx, "Delete", "-d", qid)
}

// postsuper validates qid and runs `postsuper <flag> <qid>`.
func (s *Service) postsuper(ctx context.Context, op, flag, qid string) error {
	qid, err := valid.QueueID(qid)
	if err != nil {
		return fmt.Errorf("postfixq.%s: %w", op, err)
	}
	if _, err := s.runner.Output(ctx, binPostsuper, flag, qid); err != nil {
		return fmt.Errorf("postfixq.%s %s: %w", op, qid, err)
	}
	return nil
}

// queueEntry mirrors the JSON object Postfix emits per message with `-j`
// (one object per line). Only the fields we surface are decoded.
type queueEntry struct {
	QueueName   string `json:"queue_name"`
	QueueID     string `json:"queue_id"`
	ArrivalTime int64  `json:"arrival_time"`
	MessageSize int64  `json:"message_size"`
	Sender      string `json:"sender"`
	Recipients  []struct {
		Address     string `json:"address"`
		DelayReason string `json:"delay_reason"`
	} `json:"recipients"`
}

// parseQueueJSON parses the JSONL output of `postqueue -j` into Mails. Blank
// lines are skipped; a malformed line fails the whole parse (fail closed).
func parseQueueJSON(data []byte) ([]Mail, error) {
	var mails []Mail
	sc := bufio.NewScanner(bytes.NewReader(data))
	// Queue entries can be large; raise the token limit above the 64 KiB default.
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var e queueEntry
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			// Unknown fields are tolerated: Postfix may add fields across
			// versions. Retry with a lenient decoder before giving up.
			if lerr := json.Unmarshal(raw, &e); lerr != nil {
				return nil, fmt.Errorf("parse queue line %d: %w", line, lerr)
			}
		}
		mails = append(mails, entryToMail(e))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read queue output: %w", err)
	}
	return mails, nil
}

// entryToMail flattens a decoded queue entry into a Mail, collecting recipient
// addresses and the first non-empty delay reason.
func entryToMail(e queueEntry) Mail {
	m := Mail{
		QueueID: strings.TrimSpace(e.QueueID),
		Size:    e.MessageSize,
		Arrival: formatArrival(e.ArrivalTime),
		Sender:  e.Sender,
		Status:  normalizeStatus(e.QueueName),
	}
	for _, r := range e.Recipients {
		if a := strings.TrimSpace(r.Address); a != "" {
			m.Rcpts = append(m.Rcpts, a)
		}
		if m.Reason == "" {
			m.Reason = strings.TrimSpace(r.DelayReason)
		}
	}
	return m
}
