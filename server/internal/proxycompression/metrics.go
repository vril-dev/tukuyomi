package proxycompression

import "sync/atomic"

type Status struct {
	CompressedTotal       int64
	CompressedBytesIn     int64
	CompressedBytesOut    int64
	CompressedByAlgorithm map[string]int64
	SkippedClientTotal    int64
	SkippedEncodedTotal   int64
	SkippedBodylessTotal  int64
	SkippedSmallTotal     int64
	SkippedMimeTotal      int64
	SkippedTransformTotal int64
	SkippedUpgradeTotal   int64
}

type SkipReason int

const (
	SkipClient SkipReason = iota
	SkipEncoded
	SkipBodyless
	SkipSmall
	SkipMIME
	SkipTransform
	SkipUpgrade
)

type Metrics struct {
	compressedTotal       atomic.Int64
	compressedBytesIn     atomic.Int64
	compressedBytesOut    atomic.Int64
	compressedGzipTotal   atomic.Int64
	compressedBrotliTotal atomic.Int64
	compressedZstdTotal   atomic.Int64
	skippedClientTotal    atomic.Int64
	skippedEncodedTotal   atomic.Int64
	skippedBodylessTotal  atomic.Int64
	skippedSmallTotal     atomic.Int64
	skippedMimeTotal      atomic.Int64
	skippedTransformTotal atomic.Int64
	skippedUpgradeTotal   atomic.Int64
}

func (m *Metrics) RecordCompressed(algorithm string, bytesIn, bytesOut int64) {
	if m == nil {
		return
	}
	m.compressedTotal.Add(1)
	m.compressedBytesIn.Add(bytesIn)
	m.compressedBytesOut.Add(bytesOut)
	switch algorithm {
	case AlgorithmGzip:
		m.compressedGzipTotal.Add(1)
	case AlgorithmBrotli:
		m.compressedBrotliTotal.Add(1)
	case AlgorithmZstd:
		m.compressedZstdTotal.Add(1)
	}
}

func (m *Metrics) RecordSkipped(reason SkipReason) {
	if m == nil {
		return
	}
	switch reason {
	case SkipClient:
		m.skippedClientTotal.Add(1)
	case SkipEncoded:
		m.skippedEncodedTotal.Add(1)
	case SkipBodyless:
		m.skippedBodylessTotal.Add(1)
	case SkipSmall:
		m.skippedSmallTotal.Add(1)
	case SkipMIME:
		m.skippedMimeTotal.Add(1)
	case SkipTransform:
		m.skippedTransformTotal.Add(1)
	case SkipUpgrade:
		m.skippedUpgradeTotal.Add(1)
	}
}

func (m *Metrics) Snapshot() Status {
	if m == nil {
		return Status{CompressedByAlgorithm: emptyAlgorithmSnapshot()}
	}
	return Status{
		CompressedTotal:       m.compressedTotal.Load(),
		CompressedBytesIn:     m.compressedBytesIn.Load(),
		CompressedBytesOut:    m.compressedBytesOut.Load(),
		CompressedByAlgorithm: m.byAlgorithmSnapshot(),
		SkippedClientTotal:    m.skippedClientTotal.Load(),
		SkippedEncodedTotal:   m.skippedEncodedTotal.Load(),
		SkippedBodylessTotal:  m.skippedBodylessTotal.Load(),
		SkippedSmallTotal:     m.skippedSmallTotal.Load(),
		SkippedMimeTotal:      m.skippedMimeTotal.Load(),
		SkippedTransformTotal: m.skippedTransformTotal.Load(),
		SkippedUpgradeTotal:   m.skippedUpgradeTotal.Load(),
	}
}

func (m *Metrics) byAlgorithmSnapshot() map[string]int64 {
	out := emptyAlgorithmSnapshot()
	out[AlgorithmGzip] = m.compressedGzipTotal.Load()
	out[AlgorithmBrotli] = m.compressedBrotliTotal.Load()
	out[AlgorithmZstd] = m.compressedZstdTotal.Load()
	return out
}

func emptyAlgorithmSnapshot() map[string]int64 {
	out := make(map[string]int64, len(supportedAlgorithms))
	for _, algorithm := range supportedAlgorithms {
		out[algorithm] = 0
	}
	return out
}
