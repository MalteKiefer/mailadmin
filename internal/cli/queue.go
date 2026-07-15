package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"mailadmin/internal/output"
	"mailadmin/internal/postfixq"
	"mailadmin/internal/valid"
)

// postfixq builds the Postfix queue service over the shared privileged-exec
// chokepoint. postqueue/postsuper need no config, so this never fails.
func (a *App) postfixq() *postfixq.Service {
	return postfixq.New(a.runner())
}

func newQueueCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "queue", Short: "Inspect and manage the Postfix queue"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List queued messages",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return runQueueList(app, c)
		},
	}

	show := &cobra.Command{
		Use:   "show <qid>",
		Short: "Show a queued message",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runQueueShow(app, c, args[0])
		},
	}

	flush := &cobra.Command{
		Use:   "flush",
		Short: "Flush the deferred queue",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return runQueueFlush(app, c)
		},
	}

	hold := &cobra.Command{
		Use:   "hold <qid>",
		Short: "Hold a queued message",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runQueueMutate(app, c, "hold", args[0])
		},
	}

	release := &cobra.Command{
		Use:   "release <qid>",
		Short: "Release a held message",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runQueueMutate(app, c, "release", args[0])
		},
	}

	del := &cobra.Command{
		Use:   "delete <qid>",
		Short: "Delete a queued message",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runQueueMutate(app, c, "delete", args[0])
		},
	}

	cmd.AddCommand(list, show, flush, hold, release, del)
	return cmd
}

// runQueueList renders every queued message.
func runQueueList(app *App, c *cobra.Command) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	mails, err := app.postfixq().List(ctx(c))
	if err != nil {
		return err
	}
	if app.flags.output == string(output.FormatJSON) {
		return r.JSON(mails)
	}
	t := output.Table{Columns: []string{"QUEUE ID", "STATUS", "SIZE", "ARRIVAL", "SENDER", "RECIPIENTS", "REASON"}}
	for _, m := range mails {
		t.Rows = append(t.Rows, []string{
			m.QueueID,
			m.Status,
			strconv.FormatInt(m.Size, 10),
			m.Arrival,
			m.Sender,
			joinRcpts(m.Rcpts),
			m.Reason,
		})
	}
	return r.Table(t)
}

// runQueueShow renders one message, mapping a missing id to exit 3 and an
// invalid id to exit 2.
func runQueueShow(app *App, c *cobra.Command, rawQID string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	qid, err := valid.QueueID(rawQID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	m, err := app.postfixq().Show(ctx(c), qid)
	if err != nil {
		return queueError(qid, err)
	}
	return r.Value(m)
}

// runQueueFlush attempts delivery of the whole deferred queue. It confirms
// unless --yes and records an audit entry on success.
func runQueueFlush(app *App, c *cobra.Command) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	if err := app.confirm("Flush the deferred queue (attempt delivery of all deferred mail)?"); err != nil {
		return err
	}
	if err := app.postfixq().Flush(ctx(c)); err != nil {
		return err
	}
	if err := app.recordAudit(ctx(c), "queue.flush", "", nil, nil); err != nil {
		return err
	}
	r.Message("flushed deferred queue")
	return nil
}

// runQueueMutate handles hold/release/delete: validate qid, confirm, apply, then
// audit. op is one of "hold", "release", "delete" (fixed by the command wiring).
func runQueueMutate(app *App, c *cobra.Command, op, rawQID string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	qid, err := valid.QueueID(rawQID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	action, apply, prompt := queueOp(ctx(c), app.postfixq(), op, qid)
	if err := app.confirm(prompt); err != nil {
		return err
	}
	if err := apply(); err != nil {
		return queueError(qid, err)
	}
	if err := app.recordAudit(ctx(c), action, qid, nil, nil); err != nil {
		return err
	}
	r.Message("%s %s", op, qid)
	return nil
}

// queueOp maps an operation name to its audit action, applying closure, and
// confirmation prompt.
func queueOp(ctx context.Context, svc *postfixq.Service, op, qid string) (action string, apply func() error, prompt string) {
	switch op {
	case "hold":
		return "queue.hold",
			func() error { return svc.Hold(ctx, qid) },
			fmt.Sprintf("Hold queued message %s?", qid)
	case "release":
		return "queue.release",
			func() error { return svc.Release(ctx, qid) },
			fmt.Sprintf("Release held message %s?", qid)
	default: // delete
		return "queue.delete",
			func() error { return svc.Delete(ctx, qid) },
			fmt.Sprintf("Delete queued message %s (irreversible)?", qid)
	}
}

// queueError maps backend sentinels to CLI exit-code sentinels: a missing queue
// id is not-found (exit 3), an invalid id is a usage error (exit 2).
func queueError(qid string, err error) error {
	switch {
	case errors.Is(err, postfixq.ErrNotFound):
		return fmt.Errorf("queue id %s: %w", qid, ErrNotFound)
	case errors.Is(err, valid.ErrInvalid):
		return fmt.Errorf("%w: %v", ErrUsage, err)
	default:
		return err
	}
}

// joinRcpts renders a recipient list compactly for table output.
func joinRcpts(rcpts []string) string {
	switch len(rcpts) {
	case 0:
		return ""
	case 1:
		return rcpts[0]
	default:
		return fmt.Sprintf("%s (+%d)", rcpts[0], len(rcpts)-1)
	}
}
