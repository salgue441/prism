package router

import (
	"net/http"
	"net/url"
)

// Route represents a routing rule with its handler
type Route struct {
	ID        string
	Path      string
	Method    string
	Target    *url.URL
	StripPath bool
	Handler   http.HandlerFunc
}

// Match checks if the request matches this route
func (r *Route) Match(req *http.Request) bool {
	if r.Method != "" && r.Method != req.Method {
		return false
	}

	return req.URL.Path == r.Path ||
		(len(req.URL.Path) > len(r.Path) &&
			req.URL.Path[:len(r.Path)] == r.Path &&
			req.URL.Path[len(r.Path)] == '/')
}
