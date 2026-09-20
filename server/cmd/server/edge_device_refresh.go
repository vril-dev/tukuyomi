package main

import (
	"context"
	"log"
	"time"

	"tukuyomi/internal/handler"
)

func startEdgeDeviceStatusRefreshAfterActivation(gate *workerActivationGate, interval time.Duration) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if gate != nil {
			select {
			case <-ctx.Done():
				return
			case <-gate.done:
			}
			if err := gate.wait(); err != nil {
				log.Printf("[WORKER][ACTIVATION][WARN] edge device status refresh loop not started: %v", err)
				return
			}
		}
		<-handler.StartEdgeDeviceStatusRefreshLoop(ctx, interval)
	}()
	return func() {
		cancel()
		<-done
	}
}
