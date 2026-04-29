package main

import (
	"context"
	"log"

	"tukuyomi/internal/center"
	"tukuyomi/internal/config"
)

func runCenterCommand() {
	config.LoadEnv()
	cfg, err := center.RuntimeConfigFromEnv()
	if err != nil {
		log.Fatalf("[CENTER][CONFIG][FATAL] %v", err)
	}
	if err := center.Run(context.Background(), cfg); err != nil {
		log.Fatalf("[CENTER][FATAL] %v", err)
	}
}
