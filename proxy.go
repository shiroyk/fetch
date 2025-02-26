package fetch

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
)

type roundRobinProxy struct {
	proxyURLs []*url.URL
	index     uint32
}

// getProxy returns a proxy URL for the given http.Request
func (r *roundRobinProxy) getProxy() (*url.URL, error) {
	index := atomic.AddUint32(&r.index, 1) - 1
	return r.proxyURLs[index%uint32(len(r.proxyURLs))], nil
}

// newRoundRobinProxy create the roundRobinProxy for the specified URL.
// The proxy type is determined by the URL scheme. "http", "https"
// and "socks5" are supported. If the scheme is empty,
// "http" is assumed.
func newRoundRobinProxy(proxyURLs ...string) *roundRobinProxy {
	if len(proxyURLs) == 0 {
		return nil
	}
	parsedProxyURLs := make([]*url.URL, len(proxyURLs))
	for i, pu := range proxyURLs {
		parsedURL, err := url.Parse(pu)
		if err != nil {
			slog.Error(fmt.Sprintf("proxy url %s error", pu), "error", err)
		}
		parsedProxyURLs[i] = parsedURL
	}

	return &roundRobinProxy{parsedProxyURLs, 0}
}

var requestProxyKey byte

// WithRoundRobinProxy returns a copy of parent context in which the proxies associated with context.
func WithRoundRobinProxy(ctx context.Context, proxy ...string) context.Context {
	if proxy == nil {
		return ctx
	}
	return context.WithValue(ctx, &requestProxyKey, newRoundRobinProxy(proxy...))
}

// ProxyFromRequest returns a proxy URL on request context.
func ProxyFromRequest(req *http.Request) (*url.URL, error) {
	if proxy := req.Context().Value(&requestProxyKey); proxy != nil {
		return proxy.(*roundRobinProxy).getProxy()
	}
	return nil, nil
}
