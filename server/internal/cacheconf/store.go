package cacheconf

import "sync/atomic"

var current atomic.Value

func Set(rs *Ruleset) {
	current.Store(rs)
}

func Get() *Ruleset {
	v := current.Load()

	if v == nil {
		return nil
	}

	return v.(*Ruleset)
}
