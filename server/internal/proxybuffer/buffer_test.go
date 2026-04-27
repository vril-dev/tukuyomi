package proxybuffer

import "testing"

func TestCopyBufferPoolUsesExpectedBufferSize(t *testing.T) {
	buf := GetCopyBuffer()
	if len(buf) != CopyBufferSize {
		t.Fatalf("len=%d want=%d", len(buf), CopyBufferSize)
	}
	if cap(buf) < CopyBufferSize {
		t.Fatalf("cap=%d want >=%d", cap(buf), CopyBufferSize)
	}
	PutCopyBuffer(buf[:1])

	reused := GetCopyBuffer()
	if len(reused) != CopyBufferSize {
		t.Fatalf("reused len=%d want=%d", len(reused), CopyBufferSize)
	}
}
