package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"

	"tukuyomi/internal/center"
	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

func runBootstrapCenterProtectedGatewayCommand(args []string) {
	fs := flag.NewFlagSet("bootstrap-center-protected-gateway", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	centerURL := fs.String("center-url", "", "protected Center base URL")
	gatewayAPIBasePath := fs.String("gateway-api-base-path", "", "Gateway-facing Center API base path")
	centerAPIBasePath := fs.String("center-api-base-path", "", "upstream Center API base path")
	centerUIBasePath := fs.String("center-ui-base-path", "", "Center UI base path")
	outPath := fs.String("out", "", "identity JSON output path; stdout when empty")
	deviceID := fs.String("device-id", "", "optional Gateway device ID")
	keyID := fs.String("key-id", "", "optional Gateway key ID")
	pollInterval := fs.Int("poll-interval-sec", 0, "optional Center status poll interval")
	markApproved := fs.Bool("mark-approved", false, "mark local Gateway enrollment status approved")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("[CENTER_PROTECTED][GATEWAY][FATAL] %v", err)
	}
	if fs.NArg() != 0 {
		log.Fatalf("[CENTER_PROTECTED][GATEWAY][FATAL] unexpected arguments: %v", fs.Args())
	}
	if *centerURL == "" {
		log.Fatalf("[CENTER_PROTECTED][GATEWAY][FATAL] --center-url is required")
	}

	config.LoadEnv()
	initRuntimeDBStoreOrFatal("[CENTER_PROTECTED][GATEWAY][DB]")
	result, err := handler.BootstrapCenterProtectedGateway(context.Background(), handler.CenterProtectedGatewayBootstrapOptions{
		CenterURL:                *centerURL,
		GatewayAPIBasePath:       *gatewayAPIBasePath,
		CenterAPIBasePath:        *centerAPIBasePath,
		CenterUIBasePath:         *centerUIBasePath,
		DeviceID:                 *deviceID,
		KeyID:                    *keyID,
		StatusRefreshIntervalSec: *pollInterval,
		MarkApproved:             *markApproved,
	})
	if err != nil {
		log.Fatalf("[CENTER_PROTECTED][GATEWAY][FATAL] %v", err)
	}
	if err := writeBootstrapJSON(*outPath, result); err != nil {
		log.Fatalf("[CENTER_PROTECTED][GATEWAY][FATAL] write identity: %v", err)
	}
	log.Printf("[CENTER_PROTECTED][GATEWAY] bootstrapped device_id=%s status=%s center_url=%s", result.DeviceID, result.EnrollmentStatus, result.CenterURL)
}

func runBootstrapCenterProtectedCenterCommand(args []string) {
	fs := flag.NewFlagSet("bootstrap-center-protected-center", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	inPath := fs.String("in", "", "Gateway identity JSON input path")
	outPath := fs.String("out", "", "approved device JSON output path; stdout when empty")
	actor := fs.String("actor", "system:center-protected-bootstrap", "approval actor")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("[CENTER_PROTECTED][CENTER][FATAL] %v", err)
	}
	if fs.NArg() != 0 {
		log.Fatalf("[CENTER_PROTECTED][CENTER][FATAL] unexpected arguments: %v", fs.Args())
	}
	if *inPath == "" {
		log.Fatalf("[CENTER_PROTECTED][CENTER][FATAL] --in is required")
	}

	var identity handler.CenterProtectedGatewayBootstrapResult
	if err := readBootstrapJSON(*inPath, &identity); err != nil {
		log.Fatalf("[CENTER_PROTECTED][CENTER][FATAL] read identity: %v", err)
	}
	config.LoadEnv()
	initRuntimeDBStoreOrFatal("[CENTER_PROTECTED][CENTER][DB]")
	record, err := center.BootstrapApprovedDevice(context.Background(), center.BootstrapApprovedDeviceInput{
		DeviceID:                   identity.DeviceID,
		KeyID:                      identity.KeyID,
		PublicKeyPEM:               identity.PublicKeyPEM,
		PublicKeyFingerprintSHA256: identity.PublicKeyFingerprintSHA256,
		Actor:                      *actor,
	})
	if err != nil {
		log.Fatalf("[CENTER_PROTECTED][CENTER][FATAL] %v", err)
	}
	if err := writeBootstrapJSON(*outPath, record); err != nil {
		log.Fatalf("[CENTER_PROTECTED][CENTER][FATAL] write device: %v", err)
	}
	log.Printf("[CENTER_PROTECTED][CENTER] approved device_id=%s status=%s", record.DeviceID, record.Status)
}

func readBootstrapJSON(path string, out any) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return err
	}
	return nil
}

func writeBootstrapJSON(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if path == "" {
		_, err = os.Stdout.Write(body)
		return err
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}
	return nil
}
