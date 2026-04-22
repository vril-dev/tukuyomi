package handler

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

type proxyServeContext struct {
	Writer     http.ResponseWriter
	Request    *http.Request
	ginContext *gin.Context
	aborted    bool
}

func newProxyServeContext(w http.ResponseWriter, r *http.Request) *proxyServeContext {
	return &proxyServeContext{
		Writer:  w,
		Request: r,
	}
}

func newProxyServeContextFromGin(c *gin.Context) *proxyServeContext {
	pc := &proxyServeContext{}
	if c != nil {
		pc.Writer = c.Writer
		pc.Request = c.Request
		pc.ginContext = c
	}
	return pc
}

func (c *proxyServeContext) syncGinContext() {
	if c == nil || c.ginContext == nil {
		return
	}
	c.ginContext.Request = c.Request
	if c.aborted {
		c.ginContext.Abort()
	}
}

func (c *proxyServeContext) Header(key, value string) {
	if c == nil || c.Writer == nil {
		return
	}
	c.Writer.Header().Set(key, value)
}

func (c *proxyServeContext) GetHeader(key string) string {
	if c == nil || c.Request == nil {
		return ""
	}
	return c.Request.Header.Get(key)
}

func (c *proxyServeContext) Abort() {
	if c == nil {
		return
	}
	c.aborted = true
	if c.ginContext != nil {
		c.ginContext.Abort()
	}
}

func (c *proxyServeContext) AbortWithStatus(status int) {
	if c == nil {
		return
	}
	if c.ginContext != nil {
		c.ginContext.AbortWithStatus(status)
		c.aborted = true
		return
	}
	if c.Writer == nil {
		return
	}
	c.Writer.WriteHeader(status)
	c.Abort()
}

func (c *proxyServeContext) JSON(status int, obj any) {
	if c == nil {
		return
	}
	if c.ginContext != nil {
		c.ginContext.JSON(status, obj)
		return
	}
	if c.Writer == nil {
		return
	}
	h := c.Writer.Header()
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", "application/json; charset=utf-8")
	}
	c.Writer.WriteHeader(status)
	_ = json.NewEncoder(c.Writer).Encode(obj)
}
