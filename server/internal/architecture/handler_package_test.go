package architecture

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	handlerGoFileCeiling     = 137
	handlerProdGoFileCeiling = 63
)

func TestHandlerPackageDoesNotGrow(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current test path")
	}

	handlerDir := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "handler"))
	entries, err := os.ReadDir(handlerDir)
	if err != nil {
		t.Fatalf("read internal/handler: %v", err)
	}

	total := 0
	prod := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		total++
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			prod++
		}
	}

	if total > handlerGoFileCeiling {
		t.Fatalf("internal/handler has %d Go files, ceiling is %d", total, handlerGoFileCeiling)
	}
	if prod > handlerProdGoFileCeiling {
		t.Fatalf("internal/handler has %d production Go files, ceiling is %d", prod, handlerProdGoFileCeiling)
	}
}
