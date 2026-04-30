package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func runSupervisorReleaseClientCommand(kind serverCommandKind, args []string) {
	ctx := context.Background()
	var (
		payload json.RawMessage
		err     error
	)
	switch kind {
	case serverCommandReleaseStatus:
		if len(args) != 0 {
			log.Fatalf("[RELEASE][FATAL] release-status takes no arguments")
		}
		payload, err = callSupervisorControl(ctx, http.MethodGet, "/v1/status", nil)
	case serverCommandReleaseStage:
		if len(args) != 2 {
			log.Fatalf("[RELEASE][FATAL] usage: tukuyomi release-stage <artifact> <sha256>")
		}
		payload, err = callSupervisorControl(ctx, http.MethodPost, "/v1/stage", supervisorReleaseStageRequest{
			ArtifactPath: args[0],
			SHA256:       args[1],
		})
	case serverCommandReleaseActivate:
		if len(args) != 1 {
			log.Fatalf("[RELEASE][FATAL] usage: tukuyomi release-activate <generation>")
		}
		payload, err = callSupervisorControl(ctx, http.MethodPost, "/v1/activate", supervisorReleaseActivateRequest{Generation: args[0]})
	case serverCommandReleaseRollback:
		if len(args) != 0 {
			log.Fatalf("[RELEASE][FATAL] release-rollback takes no arguments")
		}
		payload, err = callSupervisorControl(ctx, http.MethodPost, "/v1/rollback", nil)
	default:
		log.Fatalf("[RELEASE][FATAL] unsupported release command %s", kind)
	}
	if err != nil {
		log.Fatalf("[RELEASE][FATAL] %v", err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, payload, "", "  "); err != nil {
		log.Fatalf("[RELEASE][FATAL] format response: %v", err)
	}
	_, _ = os.Stdout.Write(out.Bytes())
	_, _ = os.Stdout.Write([]byte("\n"))
}
