package main

import (
	"testing"
	"time"
)

func TestEdgeDeviceStatusRefreshStopBeforeWorkerActivation(t *testing.T) {
	gate := newWorkerActivationGate()
	stop := startEdgeDeviceStatusRefreshAfterActivation(gate, time.Hour)
	stopped := make(chan struct{})
	go func() {
		stop()
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("stopping the refresh loop waited for worker activation")
	}
	gate.activate()
}

func TestEdgeDeviceStatusRefreshStopWithoutEnabledLoop(t *testing.T) {
	for _, gate := range []*workerActivationGate{nil, newWorkerActivationGate()} {
		if gate != nil {
			gate.activate()
		}
		stop := startEdgeDeviceStatusRefreshAfterActivation(gate, 0)
		stopped := make(chan struct{})
		go func() {
			stop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatal("disabled refresh loop did not stop")
		}
	}
}
