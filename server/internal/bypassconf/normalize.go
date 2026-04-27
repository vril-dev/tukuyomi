package bypassconf

import (
	"net/url"
	"path"
	"strings"
)

func normalize(p string) string {
	if p == "" {
		return "/"
	}

	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}

	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		clean += "/"
	}

	return clean
}

func eqLoosely(a, b string) bool {
	strip := func(s string) string {
		if s == "/" {
			return s
		}

		return strings.TrimSuffix(s, "/")
	}

	return strip(a) == strip(b)
}
