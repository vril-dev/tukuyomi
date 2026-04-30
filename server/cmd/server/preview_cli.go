package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

func runDBImportPreviewCommand() {
	config.LoadEnv()
	initRuntimeDBStoreOrFatal("[DB][IMPORT][PREVIEW]")
	if err := handler.ImportPreviewConfigStorage(previewBootstrapOptionsFromEnv()); err != nil {
		log.Fatalf("[DB][IMPORT][PREVIEW][FATAL] %v", err)
	}
	log.Printf("[DB][IMPORT][PREVIEW] completed")
}

func runPreviewPrintTopologyCommand() {
	config.LoadEnv()
	if previewRuntimeDBExists() {
		initRuntimeDBStoreOrFatal("[PREVIEW][TOPOLOGY]")
	}
	topology, err := handler.LoadPreviewTopology(previewBootstrapOptionsFromEnv())
	if err != nil {
		log.Fatalf("[PREVIEW][TOPOLOGY][FATAL] %v", err)
	}
	printPreviewTopology(topology)
}

func previewBootstrapOptionsFromEnv() handler.PreviewBootstrapOptions {
	return handler.PreviewBootstrapOptions{
		PublicListenAddr: strings.TrimSpace(os.Getenv("GATEWAY_PREVIEW_PUBLIC_ADDR")),
		AdminListenAddr:  strings.TrimSpace(os.Getenv("GATEWAY_PREVIEW_ADMIN_ADDR")),
	}
}

func previewRuntimeDBExists() bool {
	if strings.EqualFold(config.DBDriver, "sqlite") {
		_, err := os.Stat(config.DBPath)
		return err == nil
	}
	return true
}

func printPreviewTopology(topology handler.PreviewTopology) {
	fmt.Printf("WAF_LISTEN_PORT=%d\n", topology.PublicPort)
	fmt.Printf("CORAZA_PORT=%d\n", topology.PublicPort)
	fmt.Printf("WAF_HEALTHCHECK_PORT=%d\n", topology.HealthPort)
	fmt.Printf("GATEWAY_PREVIEW_PUBLIC_PORT=%d\n", topology.PublicPort)
	fmt.Printf("GATEWAY_PREVIEW_PUBLIC_URL=%s\n", topology.PublicURL)
	if topology.SplitAdmin {
		fmt.Printf("GATEWAY_PREVIEW_SPLIT_ADMIN=1\n")
	} else {
		fmt.Printf("GATEWAY_PREVIEW_SPLIT_ADMIN=0\n")
	}
	fmt.Printf("GATEWAY_PREVIEW_ADMIN_API_PATH=%s\n", topology.APIBasePath)
	fmt.Printf("GATEWAY_PREVIEW_ADMIN_UI_PATH=%s\n", topology.UIBasePath)
	if topology.SplitAdmin {
		fmt.Printf("WAF_ADMIN_LISTEN_PORT=%d\n", topology.AdminPort)
		fmt.Printf("CORAZA_ADMIN_PORT=%d\n", topology.AdminPort)
		fmt.Printf("GATEWAY_PREVIEW_ADMIN_PORT=%d\n", topology.AdminPort)
	} else {
		fmt.Printf("WAF_ADMIN_LISTEN_PORT=\n")
		fmt.Printf("CORAZA_ADMIN_PORT=\n")
		fmt.Printf("GATEWAY_PREVIEW_ADMIN_PORT=\n")
	}
	fmt.Printf("GATEWAY_PREVIEW_ADMIN_UI_URL=%s\n", topology.AdminUIURL)
	fmt.Printf("GATEWAY_PREVIEW_ADMIN_API_URL=%s\n", topology.AdminAPIURL)
}
