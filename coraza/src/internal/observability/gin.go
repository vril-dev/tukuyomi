package observability

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func GinTracingMiddleware() gin.HandlerFunc {
	tracer := otel.Tracer("tukuyomi/http")
	return func(c *gin.Context) {
		if !TracingEnabled() {
			c.Next()
			return
		}
		ctx := otel.GetTextMapPropagator().Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))
		name := fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path)
		ctx, span := tracer.Start(
			ctx,
			name,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", c.Request.Method),
				attribute.String("url.path", c.Request.URL.Path),
			),
		)
		c.Request = c.Request.WithContext(ctx)
		if traceID := TraceIDFromContext(ctx); traceID != "" {
			c.Writer.Header().Set("X-Trace-ID", traceID)
		}
		c.Next()
		status := c.Writer.Status()
		span.SetAttributes(attribute.Int("http.response.status_code", status))
		if len(c.Errors) > 0 {
			err := errors.New(c.Errors.String())
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else if status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(status))
		} else {
			span.SetStatus(codes.Ok, "")
		}
		span.End()
	}
}

func HTTPTracingHandler(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	tracer := otel.Tracer("tukuyomi/http")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !TracingEnabled() {
			next.ServeHTTP(w, r)
			return
		}
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		name := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		ctx, span := tracer.Start(
			ctx,
			name,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("url.path", r.URL.Path),
			),
		)
		if traceID := TraceIDFromContext(ctx); traceID != "" {
			w.Header().Set("X-Trace-ID", traceID)
		}
		sw := &httpTracingStatusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(ctx))
		status := sw.Status()
		span.SetAttributes(attribute.Int("http.response.status_code", status))
		if status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(status))
		} else {
			span.SetStatus(codes.Ok, "")
		}
		span.End()
	})
}

type httpTracingStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *httpTracingStatusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *httpTracingStatusWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func (w *httpTracingStatusWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *httpTracingStatusWriter) Size() int {
	if sizeWriter, ok := w.ResponseWriter.(interface{ Size() int }); ok {
		return sizeWriter.Size()
	}
	return 0
}

func (w *httpTracingStatusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *httpTracingStatusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *httpTracingStatusWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}
