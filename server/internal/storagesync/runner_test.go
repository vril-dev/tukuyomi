package storagesync

import (
	"errors"
	"strings"
	"testing"
)

func TestRunnerSyncRunsTasksAndAggregatesErrors(t *testing.T) {
	var order []string
	runner := NewRunner([]Task{
		{Name: "first", Run: func() error {
			order = append(order, "first")
			return nil
		}},
		{Name: "second", Run: func() error {
			order = append(order, "second")
			return errors.New("boom")
		}},
		{Name: "third", Run: func() error {
			order = append(order, "third")
			return nil
		}},
	})

	err := runner.Sync()
	if err == nil {
		t.Fatal("expected error")
	}
	if got := strings.Join(order, ","); got != "first,second,third" {
		t.Fatalf("order=%q", got)
	}
	if !strings.Contains(err.Error(), "second: boom") {
		t.Fatalf("error=%q want task context", err.Error())
	}
}

func TestRunnerCopiesTaskSlice(t *testing.T) {
	calls := 0
	tasks := []Task{{Name: "first", Run: func() error {
		calls++
		return nil
	}}}
	runner := NewRunner(tasks)
	tasks[0].Run = nil

	if err := runner.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d want 1", calls)
	}
}
