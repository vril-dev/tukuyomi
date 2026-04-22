package handler

import (
	"net/http/httputil"
	"sync"
)

const proxyReverseCopyBufferSize = 32 * 1024

var (
	proxyReverseCopyBuffers = sync.Pool{
		New: func() any {
			return make([]byte, proxyReverseCopyBufferSize)
		},
	}
	proxyReverseCopyBufferPool httputil.BufferPool = reverseProxyCopyBufferPool{}
)

type reverseProxyCopyBufferPool struct{}

func (reverseProxyCopyBufferPool) Get() []byte {
	buf, ok := proxyReverseCopyBuffers.Get().([]byte)
	if !ok || cap(buf) < proxyReverseCopyBufferSize {
		return make([]byte, proxyReverseCopyBufferSize)
	}
	return buf[:proxyReverseCopyBufferSize]
}

func (reverseProxyCopyBufferPool) Put(buf []byte) {
	if cap(buf) < proxyReverseCopyBufferSize {
		return
	}
	proxyReverseCopyBuffers.Put(buf[:proxyReverseCopyBufferSize])
}
