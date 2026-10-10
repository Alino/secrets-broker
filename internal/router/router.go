// Package router dispatches sec:// refs to the right adapter by prefix.
package router

import (
	"fmt"
	"strings"
	"sync"
)

// Resolver resolves a ref to a value (adapter implementations).
type Resolver func(ref string) (string, error)

// Router maps adapter prefixes to resolvers.
type Router struct {
	mu       sync.RWMutex
	prefixes map[string]Resolver // "opvault" -> resolver
}

func New() *Router {
	return &Router{prefixes: map[string]Resolver{}}
}

// Register binds an adapter prefix ("sec://<prefix>/...").
func (r *Router) Register(prefix string, res Resolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prefixes[prefix] = res
}

// Resolve dispatches by prefix; unknown prefix = error naming known ones.
func (r *Router) Resolve(ref string) (string, error) {
	const scheme = "sec://"
	if !strings.HasPrefix(ref, scheme) {
		return "", fmt.Errorf("router: ref must start with %s, got %q", scheme, ref)
	}
	rest := ref[len(scheme):]
	i := strings.Index(rest, "/")
	if i <= 0 {
		return "", fmt.Errorf("router: ref must be sec://<adapter>/<item>/<field>, got %q", ref)
	}
	prefix := rest[:i]
	r.mu.RLock()
	res, ok := r.prefixes[prefix]
	known := make([]string, 0, len(r.prefixes))
	for p := range r.prefixes {
		known = append(known, p)
	}
	r.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("router: no adapter %q (configured: %v)", prefix, known)
	}
	return res(ref)
}
