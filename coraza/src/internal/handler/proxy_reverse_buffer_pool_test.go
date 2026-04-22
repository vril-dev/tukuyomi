package handler

import "testing"

func TestReverseProxyCopyBufferPoolUsesExpectedBufferSize(t *testing.T) {
	buf := proxyReverseCopyBufferPool.Get()
	if len(buf) != proxyReverseCopyBufferSize {
		t.Fatalf("len=%d want=%d", len(buf), proxyReverseCopyBufferSize)
	}
	if cap(buf) < proxyReverseCopyBufferSize {
		t.Fatalf("cap=%d want >=%d", cap(buf), proxyReverseCopyBufferSize)
	}
	proxyReverseCopyBufferPool.Put(buf[:1])

	reused := proxyReverseCopyBufferPool.Get()
	if len(reused) != proxyReverseCopyBufferSize {
		t.Fatalf("reused len=%d want=%d", len(reused), proxyReverseCopyBufferSize)
	}
}
