package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

type adminMFACommandConfig struct {
	Action   string
	Username string
	Email    string
	Reason   string
}

func runAdminMFACommand(args []string) {
	cfg, err := parseAdminMFACommandConfig(args)
	if err != nil {
		log.Fatalf("[ADMIN][MFA][FATAL] %v", err)
	}
	config.LoadEnv()
	initRuntimeDBStoreOrFatal("[ADMIN][MFA][DB]")
	switch cfg.Action {
	case "disable":
		result, err := handler.DisableAdminMFAForUser(handler.AdminMFAEmergencyDisableRequest{
			Username: cfg.Username,
			Email:    cfg.Email,
			Reason:   cfg.Reason,
			Actor:    "cli",
			Now:      time.Now().UTC(),
		})
		if err != nil {
			log.Fatalf("[ADMIN][MFA][FATAL] disable failed: %v", err)
		}
		log.Printf("[ADMIN][MFA] disabled user=%s user_id=%d was_enabled=%v", result.Username, result.UserID, result.WasEnabled)
	default:
		log.Fatalf("[ADMIN][MFA][FATAL] unsupported action %q", cfg.Action)
	}
}

func parseAdminMFACommandConfig(args []string) (adminMFACommandConfig, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return adminMFACommandConfig{}, fmt.Errorf("admin-mfa requires a subcommand: disable")
	}
	action := strings.TrimSpace(args[0])
	switch action {
	case "disable":
	default:
		return adminMFACommandConfig{}, fmt.Errorf("unknown admin-mfa subcommand %q", action)
	}

	fs := flag.NewFlagSet("admin-mfa "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := adminMFACommandConfig{Action: action}
	fs.StringVar(&cfg.Username, "username", "", "admin username")
	fs.StringVar(&cfg.Email, "email", "", "admin email")
	fs.StringVar(&cfg.Reason, "reason", "", "audit reason")
	if err := fs.Parse(args[1:]); err != nil {
		return adminMFACommandConfig{}, err
	}
	if fs.NArg() != 0 {
		return adminMFACommandConfig{}, fmt.Errorf("admin-mfa %s does not accept positional arguments", action)
	}
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.Email = strings.TrimSpace(cfg.Email)
	cfg.Reason = strings.TrimSpace(cfg.Reason)
	if (cfg.Username == "") == (cfg.Email == "") {
		return adminMFACommandConfig{}, handler.ErrAdminMFAEmergencySelector
	}
	if cfg.Reason == "" {
		return adminMFACommandConfig{}, handler.ErrAdminMFAEmergencyReason
	}
	if len(cfg.Reason) > 512 || strings.ContainsAny(cfg.Reason, "\x00\r\n") {
		return adminMFACommandConfig{}, handler.ErrAdminMFAEmergencyReason
	}
	return cfg, nil
}
