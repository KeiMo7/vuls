package queue

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/future-architect/vuls/models"
)

// Handler executes one scan task.
type Handler func(context.Context, Task) (*models.ScanResult, error)

// Task is one unit of scan work.
type Task struct {
	// ID is the caller-supplied unique identifier of the task.
	ID string
	// Name is the human-readable task name.
	Name string
	// Family is the OS family associated with the task.
	Family string
	// Release is the OS release associated with the task.
	Release string
	// Index is the zero-based enqueue order assigned by Submit.
	Index int
	// Attempt is the current one-based attempt number.
	Attempt int
	// EnqueuedAt is the time at which the task was submitted.
	EnqueuedAt time.Time
}

// Options configures a bounded task queue.
type Options struct {
	// Workers is the maximum number of tasks occupying a worker slot.
	Workers int
	// MaxAttempts is the maximum number of attempts for retryable failures.
	MaxAttempts int
	// Backoff is the delay used before the first retry.
	Backoff time.Duration
	// MaxBackoff caps exponential backoff when positive.
	MaxBackoff time.Duration
	// TaskTimeout bounds each attempt when positive.
	TaskTimeout time.Duration
	// Now returns the current time; time.Now is used when nil.
	Now func() time.Time
	// Sleep waits for d and must respond to context cancellation.
	Sleep func(context.Context, time.Duration) error
}

// Outcome is the terminal or snapshot state of one task.
type Outcome struct {
	// Task is the task value associated with this outcome.
	Task Task
	// State is the current lifecycle state.
	State State
	// Attempts is the number of attempts started or reserved for retry.
	Attempts int
	// StartedAt is the first attempt start time.
	StartedAt time.Time
	// FinishedAt is the terminal transition time.
	FinishedAt time.Time
	// Err is the terminal or latest task error, if any.
	Err error
}

// Report is the result of running a queue.
type Report struct {
	// Outcomes contains every task outcome sorted by Task.Index.
	Outcomes []Outcome
	// Succeeded is the number of succeeded tasks.
	Succeeded int
	// Failed is the number of failed tasks.
	Failed int
	// Canceled is the number of canceled tasks.
	Canceled int
	// Retried is the total number of retry attempts.
	Retried int
	// MaxInFlight is the high-water mark of occupied worker slots.
	MaxInFlight int
	// Elapsed is the wall-clock duration of Run.
	Elapsed time.Duration
}

// Queue is a bounded-concurrency scan task queue.
type Queue struct {
	opts Options

	mu          sync.Mutex
	outcomes    []Outcome
	byID        map[string]int
	nextClaim   int
	closed      bool
	inFlight    int
	maxInFlight int
}

// New validates options and creates a Queue.
func New(opts Options) (*Queue, error) {
	if opts.Workers < 1 {
		return nil, fmt.Errorf("%w: Workers must be at least 1", ErrInvalidOptions)
	}
	if opts.MaxAttempts < 1 {
		return nil, fmt.Errorf("%w: MaxAttempts must be at least 1", ErrInvalidOptions)
	}
	if opts.Backoff < 0 {
		return nil, fmt.Errorf("%w: Backoff must not be negative", ErrInvalidOptions)
	}
	if opts.MaxBackoff < 0 {
		return nil, fmt.Errorf("%w: MaxBackoff must not be negative", ErrInvalidOptions)
	}
	if opts.TaskTimeout < 0 {
		return nil, fmt.Errorf("%w: TaskTimeout must not be negative", ErrInvalidOptions)
	}
	if opts.MaxBackoff > 0 && opts.MaxBackoff < opts.Backoff {
		return nil, fmt.Errorf("%w: MaxBackoff must not be shorter than Backoff", ErrInvalidOptions)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = defaultSleep
	}

	return &Queue{
		opts: opts,
		byID: make(map[string]int),
	}, nil
}

// Submit adds one task to the queue.
func (q *Queue) Submit(task Task) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return ErrClosed
	}
	if task.ID == "" || task.Name == "" {
		return fmt.Errorf("%w: ID and Name are required", ErrInvalidTask)
	}
	if _, exists := q.byID[task.ID]; exists {
		return fmt.Errorf("%w: %q", ErrDuplicateTask, task.ID)
	}

	task.Index = len(q.outcomes)
	task.Attempt = 1
	if task.EnqueuedAt.IsZero() {
		task.EnqueuedAt = q.opts.Now()
	}

	q.byID[task.ID] = task.Index
	q.outcomes = append(q.outcomes, Outcome{
		Task:  task,
		State: StatePending,
	})
	return nil
}

// Snapshot returns a sorted copy of all current outcomes.
func (q *Queue) Snapshot() []Outcome {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.snapshotLocked()
}

func (q *Queue) snapshotLocked() []Outcome {
	out := make([]Outcome, len(q.outcomes))
	copy(out, q.outcomes)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Task.Index < out[j].Task.Index
	})
	return out
}

// Run executes all submitted tasks with bounded concurrency.
func (q *Queue) Run(ctx context.Context, handler Handler) (Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return Report{}, ErrClosed
	}
	q.closed = true
	start := q.opts.Now()
	workers := q.opts.Workers
	q.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				idx, ok := q.claim(ctx)
				if !ok {
					return
				}
				q.execute(ctx, handler, idx)
			}
		}()
	}
	wg.Wait()

	q.mu.Lock()
	outcomes := q.snapshotLocked()
	maxInFlight := q.maxInFlight
	q.mu.Unlock()

	report := Report{
		Outcomes:    outcomes,
		MaxInFlight: maxInFlight,
		Elapsed:     q.opts.Now().Sub(start),
	}
	for _, outcome := range outcomes {
		switch outcome.State {
		case StateSucceeded:
			report.Succeeded++
		case StateFailed:
			report.Failed++
		case StateCanceled:
			report.Canceled++
		}
		if outcome.Attempts > 1 {
			report.Retried += outcome.Attempts - 1
		}
	}
	return report, nil
}

// RunTasks creates a queue, submits tasks, and runs them.
func RunTasks(ctx context.Context, opts Options, tasks []Task, handler Handler) (Report, error) {
	q, err := New(opts)
	if err != nil {
		return Report{}, err
	}
	for _, task := range tasks {
		if err := q.Submit(task); err != nil {
			return Report{}, err
		}
	}
	return q.Run(ctx, handler)
}

func (q *Queue) claim(ctx context.Context) (int, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for q.nextClaim < len(q.outcomes) {
		idx := q.nextClaim
		q.nextClaim++
		outcome := &q.outcomes[idx]

		if err := ctx.Err(); err != nil {
			if transitionErr := Transition(outcome.State, StateCanceled); transitionErr == nil {
				outcome.State = StateCanceled
				outcome.Err = err
			}
			continue
		}

		if err := Transition(outcome.State, StateRunning); err != nil {
			continue
		}
		now := q.opts.Now()
		outcome.State = StateRunning
		outcome.StartedAt = now
		outcome.Attempts = 1
		outcome.Task.Attempt = 1

		q.inFlight++
		if q.inFlight > q.maxInFlight {
			q.maxInFlight = q.inFlight
		}
		return idx, true
	}
	return 0, false
}

func (q *Queue) execute(parent context.Context, handler Handler, idx int) {
	defer q.releaseSlot()

	attempt := 1
	for {
		task := q.task(idx)
		attemptCtx, cancelAttempt := parent, func() {}
		if q.opts.TaskTimeout > 0 {
			attemptCtx, cancelAttempt = context.WithTimeout(parent, q.opts.TaskTimeout)
		}

		result, err, panicValue := invokeHandler(attemptCtx, handler, task)
		cancelAttempt()

		if parent.Err() != nil {
			q.cancelActive(idx, parent.Err())
			return
		}
		if panicValue != nil {
			q.fail(idx, fmt.Errorf("%w: %v", ErrPanic, panicValue))
			return
		}
		if err == nil && result == nil {
			q.fail(idx, fmt.Errorf("%w: task %q returned nil result and nil error", ErrNilResult, task.ID))
			return
		}
		if err != nil {
			err = classifyTimeout(err, attemptCtx)
			if attempt < q.opts.MaxAttempts && isRetryable(err) {
				nextAttempt := attempt + 1
				q.beginRetry(idx, nextAttempt)
				delay := backoffDelay(q.opts.Backoff, nextAttempt, q.opts.MaxBackoff)
				sleepErr := q.opts.Sleep(parent, delay)
				if sleepErr != nil || parent.Err() != nil {
					cause := sleepErr
					if cause == nil {
						cause = parent.Err()
					}
					q.cancelActive(idx, cause)
					return
				}
				q.resumeRunning(idx)
				attempt = nextAttempt
				continue
			}
			q.fail(idx, fmt.Errorf("task %q failed after %d attempt(s): %w", task.ID, attempt, err))
			return
		}

		q.succeed(idx)
		return
	}
}

func invokeHandler(ctx context.Context, handler Handler, task Task) (result *models.ScanResult, err error, panicValue any) {
	defer func() {
		if p := recover(); p != nil {
			panicValue = p
		}
	}()
	result, err = handler(ctx, task)
	return result, err, nil
}

func (q *Queue) task(idx int) Task {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.outcomes[idx].Task
}

func (q *Queue) releaseSlot() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.inFlight > 0 {
		q.inFlight--
	}
}

func (q *Queue) beginRetry(idx, nextAttempt int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	outcome := &q.outcomes[idx]
	if err := Transition(outcome.State, StateRetrying); err == nil {
		outcome.State = StateRetrying
	}
	outcome.Attempts = nextAttempt
	outcome.Task.Attempt = nextAttempt
}

func (q *Queue) resumeRunning(idx int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	outcome := &q.outcomes[idx]
	if err := Transition(outcome.State, StateRunning); err == nil {
		outcome.State = StateRunning
	}
}

func (q *Queue) succeed(idx int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	outcome := &q.outcomes[idx]
	if err := Transition(outcome.State, StateSucceeded); err == nil {
		outcome.State = StateSucceeded
	}
	outcome.FinishedAt = q.opts.Now()
}

func (q *Queue) fail(idx int, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	outcome := &q.outcomes[idx]
	if transitionErr := Transition(outcome.State, StateFailed); transitionErr == nil {
		outcome.State = StateFailed
	}
	outcome.FinishedAt = q.opts.Now()
	outcome.Err = err
}

func (q *Queue) cancelActive(idx int, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	outcome := &q.outcomes[idx]
	if transitionErr := Transition(outcome.State, StateCanceled); transitionErr == nil {
		outcome.State = StateCanceled
	}
	outcome.FinishedAt = q.opts.Now()
	outcome.Err = err
}

type retryableError interface {
	Retryable() bool
}

func isRetryable(err error) bool {
	if errors.Is(err, ErrTransient) || errors.Is(err, ErrTimeout) {
		return true
	}
	var retryable retryableError
	if errors.As(err, &retryable) {
		return retryable.Retryable()
	}
	return false
}

func classifyTimeout(err error, attemptCtx context.Context) error {
	timedOut := errors.Is(err, context.DeadlineExceeded) || errors.Is(attemptCtx.Err(), context.DeadlineExceeded)
	if !timedOut {
		return err
	}
	return fmt.Errorf("%w: %w: %w", ErrTimeout, context.DeadlineExceeded, err)
}

func backoffDelay(base time.Duration, attempt int, max time.Duration) time.Duration {
	delay := base
	for n := 2; n < attempt; n++ {
		switch {
		case max > 0 && delay > max/2:
			delay = max
		case max > 0:
			delay *= 2
			if delay > max {
				delay = max
			}
		case delay > math.MaxInt64/2:
			delay = math.MaxInt64
		default:
			delay *= 2
		}
	}
	if max > 0 && delay > max {
		delay = max
	}
	return delay
}

func defaultSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
