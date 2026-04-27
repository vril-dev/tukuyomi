package storagesync

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

type Task struct {
	Name string
	Run  func() error
}

type Runner struct {
	mu    sync.Mutex
	tasks []Task
}

func NewRunner(tasks []Task) *Runner {
	return &Runner{tasks: append([]Task(nil), tasks...)}
}

func (r *Runner) Sync() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for _, task := range r.tasks {
		if task.Run == nil {
			continue
		}
		if err := task.Run(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", task.Name, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func StartLoop(interval time.Duration, syncFn func() error, warn func(error)) {
	if interval <= 0 || syncFn == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := syncFn(); err != nil && warn != nil {
				warn(err)
			}
		}
	}()
}
