package queue

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/future-architect/vuls/models"
)

func testOpts() Options {
	return Options{Workers: 2, MaxAttempts: 1}
}

func okHandler() Handler {
	return func(context.Context, Task) (*models.ScanResult, error) {
		return &models.ScanResult{}, nil
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{name: "workers zero", opts: Options{Workers: 0, MaxAttempts: 1}},
		{name: "workers negative", opts: Options{Workers: -1, MaxAttempts: 1}},
		{name: "attempts zero", opts: Options{Workers: 1, MaxAttempts: 0}},
		{name: "attempts negative", opts: Options{Workers: 1, MaxAttempts: -1}},
		{name: "negative backoff", opts: Options{Workers: 1, MaxAttempts: 1, Backoff: -time.Nanosecond}},
		{name: "negative max backoff", opts: Options{Workers: 1, MaxAttempts: 1, MaxBackoff: -time.Nanosecond}},
		{name: "negative task timeout", opts: Options{Workers: 1, MaxAttempts: 1, TaskTimeout: -time.Nanosecond}},
		{name: "max backoff shorter", opts: Options{Workers: 1, MaxAttempts: 1, Backoff: 20 * time.Millisecond, MaxBackoff: 10 * time.Millisecond}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts)
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("New() error = %v, want ErrInvalidOptions", err)
			}
		})
	}

	q, err := New(Options{Workers: 1, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if q.opts.Now == nil || q.opts.Sleep == nil {
		t.Fatal("default Now/Sleep were not filled")
	}
}

func TestSubmitAndRunErrors(t *testing.T) {
	t.Run("empty id", func(t *testing.T) {
		q, _ := New(testOpts())
		err := q.Submit(Task{Name: "n"})
		if !errors.Is(err, ErrInvalidTask) {
			t.Fatalf("Submit() error = %v, want ErrInvalidTask", err)
		}
	})

	t.Run("empty name", func(t *testing.T) {
		q, _ := New(testOpts())
		err := q.Submit(Task{ID: "id"})
		if !errors.Is(err, ErrInvalidTask) {
			t.Fatalf("Submit() error = %v, want ErrInvalidTask", err)
		}
	})

	t.Run("duplicate id", func(t *testing.T) {
		q, _ := New(testOpts())
		task := Task{ID: "id", Name: "name"}
		if err := q.Submit(task); err != nil {
			t.Fatal(err)
		}
		err := q.Submit(task)
		if !errors.Is(err, ErrDuplicateTask) {
			t.Fatalf("second Submit() error = %v, want ErrDuplicateTask", err)
		}
	})

	t.Run("submit after run and second run", func(t *testing.T) {
		q, _ := New(testOpts())
		if err := q.Submit(Task{ID: "id", Name: "name"}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Run(context.Background(), okHandler()); err != nil {
			t.Fatal(err)
		}

		err := q.Submit(Task{ID: "later", Name: "later"})
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Submit after Run error = %v, want ErrClosed", err)
		}
		_, err = q.Run(context.Background(), okHandler())
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("second Run error = %v, want ErrClosed", err)
		}
	})
}

func TestTransition(t *testing.T) {
	legal := map[State][]State{
		StatePending:  {StateRunning, StateCanceled},
		StateRunning:  {StateRetrying, StateSucceeded, StateFailed, StateCanceled},
		StateRetrying: {StateRunning, StateCanceled},
	}
	all := []State{StatePending, StateRunning, StateRetrying, StateSucceeded, StateFailed, StateCanceled}

	for from, targets := range legal {
		for _, to := range targets {
			if err := Transition(from, to); err != nil {
				t.Errorf("Transition(%s,%s) returned unexpected error: %v", from, to, err)
			}
		}
	}

	legalSet := make(map[[2]State]bool)
	for from, targets := range legal {
		for _, to := range targets {
			legalSet[[2]State{from, to}] = true
		}
	}
	for _, from := range all {
		for _, to := range all {
			if legalSet[[2]State{from, to}] {
				continue
			}
			err := Transition(from, to)
			if !errors.Is(err, ErrInvalidTransition) {
				t.Errorf("Transition(%s,%s) error = %v, want ErrInvalidTransition", from, to, err)
			}
		}
	}
}

func TestSnapshotPending(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	q, err := New(Options{Workers: 1, MaxAttempts: 1, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Submit(Task{ID: "a", Name: "A"}); err != nil {
		t.Fatal(err)
	}

	snapshot := q.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("len(Snapshot()) = %d, want 1", len(snapshot))
	}
	got := snapshot[0]
	if got.State != StatePending || got.Task.Index != 0 || got.Task.Attempt != 1 {
		t.Fatalf("unexpected pending outcome: %+v", got)
	}
	if !got.StartedAt.IsZero() || !got.FinishedAt.IsZero() {
		t.Fatalf("pending outcome has timestamps: %+v", got)
	}
	if !got.Task.EnqueuedAt.Equal(now) {
		t.Fatalf("EnqueuedAt = %v, want %v", got.Task.EnqueuedAt, now)
	}
}

func TestBoundedConcurrency(t *testing.T) {
	const total = 8
	const workers = 3

	q, err := New(Options{Workers: workers, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < total; i++ {
		if err := q.Submit(Task{ID: fmt.Sprintf("t%d", i), Name: fmt.Sprintf("task-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}

	var active, peak int32
	var once sync.Once
	barrier := make(chan struct{})
	report, err := q.Run(context.Background(), func(context.Context, Task) (*models.ScanResult, error) {
		current := atomic.AddInt32(&active, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if current <= old || atomic.CompareAndSwapInt32(&peak, old, current) {
				break
			}
		}
		if current == workers {
			once.Do(func() { close(barrier) })
		}
		select {
		case <-barrier:
		case <-time.After(2 * time.Second):
			t.Error("timed out waiting for three concurrent handlers")
		}
		atomic.AddInt32(&active, -1)
		return &models.ScanResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if peak != workers {
		t.Fatalf("atomic peak concurrency = %d, want %d", peak, workers)
	}
	if report.MaxInFlight != workers {
		t.Fatalf("Report.MaxInFlight = %d, want %d", report.MaxInFlight, workers)
	}
	if report.Succeeded != total {
		t.Fatalf("Succeeded = %d, want %d", report.Succeeded, total)
	}
}

func TestOutcomesSortedByIndex(t *testing.T) {
	q, err := New(Options{Workers: 3, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := q.Submit(Task{ID: fmt.Sprintf("t%d", i), Name: fmt.Sprintf("task-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}

	started := make(chan struct{})
	release := make(chan struct{})
	type runResult struct {
		report Report
		err    error
	}
	done := make(chan runResult, 1)
	go func() {
		report, err := q.Run(context.Background(), func(_ context.Context, task Task) (*models.ScanResult, error) {
			if task.Index == 0 {
				close(started)
				<-release
			}
			return &models.ScanResult{}, nil
		})
		done <- runResult{report: report, err: err}
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("task 0 did not start")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		snapshot := q.Snapshot()
		if len(snapshot) == 3 && snapshot[1].State == StateSucceeded && snapshot[2].State == StateSucceeded {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		for i, outcome := range result.report.Outcomes {
			if outcome.Task.Index != i {
				t.Fatalf("Outcomes[%d].Index = %d, want %d", i, outcome.Task.Index, i)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not finish after releasing slowest task")
	}

	_, err = q.Run(context.Background(), okHandler())
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("second Run error = %v, want ErrClosed", err)
	}
}

type retryableErr struct{ retry bool }

func (e retryableErr) Error() string   { return "retryable" }
func (e retryableErr) Retryable() bool { return e.retry }

func TestBackoffSequenceAndRetryLimits(t *testing.T) {
	var waits []time.Duration
	var sleepMu sync.Mutex
	opts := Options{
		Workers:     1,
		MaxAttempts: 4,
		Backoff:     10 * time.Millisecond,
		MaxBackoff:  25 * time.Millisecond,
		Sleep: func(_ context.Context, d time.Duration) error {
			sleepMu.Lock()
			waits = append(waits, d)
			sleepMu.Unlock()
			return nil
		},
	}
	q, _ := New(opts)
	_ = q.Submit(Task{ID: "t", Name: "t"})

	var calls int32
	report, err := q.Run(context.Background(), func(context.Context, Task) (*models.ScanResult, error) {
		atomic.AddInt32(&calls, 1)
		return nil, fmt.Errorf("wrapped: %w", ErrTransient)
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("handler calls = %d, want 4", calls)
	}
	if report.Failed != 1 || report.Retried != 3 {
		t.Fatalf("Failed=%d Retried=%d, want 1 and 3", report.Failed, report.Retried)
	}
	outcome := report.Outcomes[0]
	if outcome.State != StateFailed || outcome.Attempts != 4 || outcome.Task.Attempt != 4 {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	if !errors.Is(outcome.Err, ErrTransient) {
		t.Fatalf("outcome error %v does not wrap ErrTransient", outcome.Err)
	}
	wantWaits := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 25 * time.Millisecond}
	if len(waits) != len(wantWaits) {
		t.Fatalf("waits = %v, want %v", waits, wantWaits)
	}
	for i := range wantWaits {
		if waits[i] != wantWaits[i] {
			t.Fatalf("waits = %v, want %v", waits, wantWaits)
		}
	}
}

func TestRetryClassification(t *testing.T) {
	t.Run("retryable interface", func(t *testing.T) {
		q, _ := New(Options{Workers: 1, MaxAttempts: 2, Sleep: noSleep()})
		_ = q.Submit(Task{ID: "t", Name: "t"})
		var calls int32
		report, _ := q.Run(context.Background(), func(context.Context, Task) (*models.ScanResult, error) {
			atomic.AddInt32(&calls, 1)
			return nil, retryableErr{retry: true}
		})
		if calls != 2 || report.Outcomes[0].Attempts != 2 || report.Retried != 1 {
			t.Fatalf("calls=%d report=%+v", calls, report)
		}
	})

	t.Run("non retryable", func(t *testing.T) {
		slept := false
		q, _ := New(Options{Workers: 1, MaxAttempts: 3, Sleep: func(context.Context, time.Duration) error {
			slept = true
			return nil
		}})
		_ = q.Submit(Task{ID: "t", Name: "t"})
		var calls int32
		report, _ := q.Run(context.Background(), func(context.Context, Task) (*models.ScanResult, error) {
			atomic.AddInt32(&calls, 1)
			return nil, errors.New("permanent")
		})
		if calls != 1 || report.Outcomes[0].Attempts != 1 || report.Retried != 0 {
			t.Fatalf("calls=%d report=%+v", calls, report)
		}
		if slept {
			t.Fatal("backoff slept for a non-retryable error")
		}
	})
}

func noSleep() func(context.Context, time.Duration) error {
	return func(context.Context, time.Duration) error { return nil }
}

func TestAttemptTimeout(t *testing.T) {
	q, _ := New(Options{
		Workers:     1,
		MaxAttempts: 2,
		TaskTimeout: 20 * time.Millisecond,
		Sleep:       noSleep(),
	})
	_ = q.Submit(Task{ID: "timeout", Name: "timeout"})

	var calls int32
	report, _ := q.Run(context.Background(), func(ctx context.Context, _ Task) (*models.ScanResult, error) {
		atomic.AddInt32(&calls, 1)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	outcome := report.Outcomes[0]
	if outcome.State != StateFailed || outcome.Attempts != 2 {
		t.Fatalf("unexpected timeout outcome: %+v", outcome)
	}
	if outcome.StartedAt.IsZero() {
		t.Fatal("StartedAt is zero for a running attempt")
	}
	if !errors.Is(outcome.Err, ErrTimeout) {
		t.Errorf("error %v does not match ErrTimeout", outcome.Err)
	}
	if !errors.Is(outcome.Err, context.DeadlineExceeded) {
		t.Errorf("error %v does not match context.DeadlineExceeded", outcome.Err)
	}
}

func TestContextCancellationCancelsPending(t *testing.T) {
	q, _ := New(Options{Workers: 1, MaxAttempts: 3, Sleep: noSleep()})
	for _, id := range []string{"running", "pending1", "pending2"} {
		_ = q.Submit(Task{ID: id, Name: id})
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	type runResult struct {
		report Report
		err    error
	}
	done := make(chan runResult, 1)
	go func() {
		report, err := q.Run(ctx, func(handlerCtx context.Context, task Task) (*models.ScanResult, error) {
			if task.ID == "running" {
				close(started)
				cancel()
				<-handlerCtx.Done()
				return nil, handlerCtx.Err()
			}
			return &models.ScanResult{}, nil
		})
		done <- runResult{report: report, err: err}
	}()
	<-started

	var report Report
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		report = result.report
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}

	if report.Canceled != 3 {
		t.Fatalf("Canceled = %d, want 3; report=%+v", report.Canceled, report)
	}
	byID := mapOutcomes(report.Outcomes)
	running := byID["running"]
	if running.State != StateCanceled || running.Attempts != 1 || running.StartedAt.IsZero() {
		t.Fatalf("bad running canceled outcome: %+v", running)
	}
	for _, id := range []string{"pending1", "pending2"} {
		outcome := byID[id]
		if outcome.State != StateCanceled {
			t.Errorf("%s state = %s, want canceled", id, outcome.State)
		}
		if outcome.Attempts != 0 || !outcome.StartedAt.IsZero() || !outcome.FinishedAt.IsZero() {
			t.Errorf("%s pending outcome has attempts/timestamps: %+v", id, outcome)
		}
	}
}

func mapOutcomes(outcomes []Outcome) map[string]Outcome {
	m := make(map[string]Outcome, len(outcomes))
	for _, outcome := range outcomes {
		m[outcome.Task.ID] = outcome
	}
	return m
}

func TestPanicAndNilResult(t *testing.T) {
	q, _ := New(Options{Workers: 3, MaxAttempts: 3, Sleep: noSleep()})
	for _, id := range []string{"panic", "nil", "ok"} {
		_ = q.Submit(Task{ID: id, Name: id})
	}

	report, _ := q.Run(context.Background(), func(_ context.Context, task Task) (*models.ScanResult, error) {
		switch task.ID {
		case "panic":
			panic("boom-value")
		case "nil":
			return nil, nil
		default:
			return &models.ScanResult{}, nil
		}
	})
	if report.Succeeded != 1 || report.Failed != 2 {
		t.Fatalf("Succeeded=%d Failed=%d, want 1 and 2", report.Succeeded, report.Failed)
	}
	byID := mapOutcomes(report.Outcomes)
	panicked := byID["panic"]
	if panicked.Attempts != 1 || !errors.Is(panicked.Err, ErrPanic) {
		t.Fatalf("panic outcome = %+v", panicked)
	}
	if panicked.Err == nil || !strings.Contains(panicked.Err.Error(), "boom-value") {
		t.Fatalf("panic error %v does not contain panic value", panicked.Err)
	}
	nilOutcome := byID["nil"]
	if nilOutcome.Attempts != 1 || !errors.Is(nilOutcome.Err, ErrNilResult) {
		t.Fatalf("nil outcome = %+v", nilOutcome)
	}
	if byID["ok"].State != StateSucceeded {
		t.Fatalf("ok outcome = %+v", byID["ok"])
	}
}

func TestSnapshotAndReportCopiesAreIsolated(t *testing.T) {
	q, _ := New(Options{Workers: 2, MaxAttempts: 1})
	_ = q.Submit(Task{ID: "a", Name: "a"})
	_ = q.Submit(Task{ID: "b", Name: "b"})

	var calls int32
	report, _ := q.Run(context.Background(), func(context.Context, Task) (*models.ScanResult, error) {
		atomic.AddInt32(&calls, 1)
		return &models.ScanResult{}, nil
	})

	snapshot := q.Snapshot()
	if len(snapshot) != 2 {
		t.Fatalf("snapshot length = %d", len(snapshot))
	}
	snapshot[0] = Outcome{State: StateFailed}
	snapshot = append(snapshot, Outcome{Task: Task{ID: "extra"}})
	report.Outcomes[0] = Outcome{State: StateFailed}

	again := q.Snapshot()
	if len(again) != 2 || again[0].State != StateSucceeded {
		t.Fatalf("internal outcomes changed through copy: %+v", again)
	}

	before := atomic.LoadInt32(&calls)
	time.Sleep(100 * time.Millisecond)
	after := atomic.LoadInt32(&calls)
	if before != after {
		t.Fatalf("handler calls grew after Run: before=%d after=%d", before, after)
	}
}

func TestRunTasksConvenience(t *testing.T) {
	tasks := []Task{{ID: "a", Name: "a"}, {ID: "b", Name: "b"}}
	report, err := RunTasks(context.Background(), Options{Workers: 2, MaxAttempts: 1}, tasks, okHandler())
	if err != nil {
		t.Fatal(err)
	}
	if report.Succeeded != 2 || len(report.Outcomes) != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
}
