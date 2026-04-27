package proxyserve

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Context struct {
	Writer     http.ResponseWriter
	Request    *http.Request
	ginContext *gin.Context
	aborted    bool
}

func New(w http.ResponseWriter, r *http.Request) *Context {
	return &Context{
		Writer:  w,
		Request: r,
	}
}

func NewFromGin(c *gin.Context) *Context {
	pc := &Context{}
	if c != nil {
		pc.Writer = c.Writer
		pc.Request = c.Request
		pc.ginContext = c
	}
	return pc
}

func (c *Context) SyncGinContext() {
	if c == nil || c.ginContext == nil {
		return
	}
	c.ginContext.Request = c.Request
	if c.aborted {
		c.ginContext.Abort()
	}
}

func (c *Context) Header(key, value string) {
	if c == nil || c.Writer == nil {
		return
	}
	c.Writer.Header().Set(key, value)
}

func (c *Context) GetHeader(key string) string {
	if c == nil || c.Request == nil {
		return ""
	}
	return c.Request.Header.Get(key)
}

func (c *Context) Abort() {
	if c == nil {
		return
	}
	c.aborted = true
	if c.ginContext != nil {
		c.ginContext.Abort()
	}
}

func (c *Context) AbortWithStatus(status int) {
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

func (c *Context) JSON(status int, obj any) {
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
