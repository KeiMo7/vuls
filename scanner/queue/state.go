package queue

import (
	"errors"
	"fmt"
)

// State is the lifecycle state of a queued task.
type State string

const (
	// StatePending means the task has been submitted but has not started.
	StatePending State = "pending"
	// StateRunning means an attempt is currently executing.
	StateRunning State = "running"
	// StateRetrying means a failed attempt is waiting for another attempt.
	StateRetrying State = "retrying"
	// StateSucceeded means the task completed successfully.
	StateSucceeded State = "succeeded"
	// StateFailed means the task terminated with a non-retryable or exhausted error.
	StateFailed State = "failed"
	// StateCanceled means the task was canceled by its context.
	StateCanceled State = "canceled"
)

var allowedTransitions = map[State]map[State]struct{}{
	StatePending: {
		StateRunning:  {},
		StateCanceled: {},
	},
	StateRunning: {
		StateRetrying:  {},
		StateSucceeded: {},
		StateFailed:    {},
		StateCanceled:  {},
	},
	StateRetrying: {
		StateRunning:  {},
		StateCanceled: {},
	},
}

// Transition validates a state transition.
func Transition(from, to State) error {
	if next, ok := allowedTransitions[from]; ok {
		if _, ok := next[to]; ok {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot transition from %q to %q", ErrInvalidTransition, from, to)
}

var (
	// ErrDuplicateTask is returned when a task ID is already queued.
	ErrDuplicateTask = errors.New("duplicate task ID")
	// ErrInvalidTask is returned when a task is missing required fields.
	ErrInvalidTask = errors.New("invalid task")
	// ErrInvalidOptions is returned when queue options fail validation.
	ErrInvalidOptions = errors.New("invalid queue options")
	// ErrInvalidTransition is returned for an illegal task state transition.
	ErrInvalidTransition = errors.New("invalid task state transition")
	// ErrClosed is returned when a queue is submitted to or run after closure.
	ErrClosed = errors.New("queue is closed")
	// ErrTransient marks an error as eligible for another attempt.
	ErrTransient = errors.New("transient task error")
	// ErrNilResult is returned when a handler returns nil result and nil error.
	ErrNilResult = errors.New("handler returned a nil result")
	// ErrTimeout marks an attempt timeout.
	ErrTimeout = errors.New("task attempt timed out")
	// ErrPanic marks a recovered handler panic.
	ErrPanic = errors.New("handler panicked")
)
