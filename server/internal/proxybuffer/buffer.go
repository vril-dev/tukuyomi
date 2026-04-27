package proxybuffer

import "sync"

const CopyBufferSize = 32 * 1024

var copyBuffers = sync.Pool{
	New: func() any {
		return make([]byte, CopyBufferSize)
	},
}

func GetCopyBuffer() []byte {
	buf, ok := copyBuffers.Get().([]byte)
	if !ok || cap(buf) < CopyBufferSize {
		return make([]byte, CopyBufferSize)
	}
	return buf[:CopyBufferSize]
}

func PutCopyBuffer(buf []byte) {
	if cap(buf) < CopyBufferSize {
		return
	}
	copyBuffers.Put(buf[:CopyBufferSize])
}
