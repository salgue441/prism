package router

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	if r.Method != "" && !strings.EqualFold(r.Method, req.Method) {
		return false
	}

	return r.matchPath(req.URL.Path)
}

// String returns a string representation of the route
func (r *Route) String() string {
	method := r.Method
	if method == "" {
		method = "*"
	}
	
	return fmt.Sprintf("%s %s -> %s", method, r.Path, r.Target.String())
}

// Private methods

// matchPath checks if the request path matches the route path
func (r *Route) matchPath(requestPath string) bool {
	if r.Path == requestPath {
		return true
	}

	if strings.HasSuffix(r.Path, "/*") {
		prefix := strings.TrimSuffix(r.Path, "/*")
		return strings.HasPrefix(requestPath, prefix)
	}

	if strings.HasSuffix(r.Path, "/") {
		return strings.HasPrefix(requestPath, r.Path)
	}

	if len(requestPath) > len(r.Path) &&
		strings.HasPrefix(requestPath, r.Path) &&
		requestPath[len(r.Path)] == '/' {
		return true
	}

	return false
}
