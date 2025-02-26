package fetch

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/shiroyk/fetch/http2"
	"golang.org/x/net/html/charset"
)

type Fetch struct {
	*http.Client
	charsetAutoDetect bool
	maxBodySize       int64
	retryTimes        uint
	retryHTTPCodes    []int
	timeout           time.Duration
	headers           http.Header
}

const (
	// DefaultMaxBodySize fetch.Response default max body size
	DefaultMaxBodySize int64 = 1024 * 1024 * 1024
	// DefaultRetryTimes fetch.RequestConfig retry times
	DefaultRetryTimes = 3
	// DefaultTimeout fetch.RequestConfig timeout
	DefaultTimeout = time.Minute
)

var (
	// DefaultRetryHTTPCodes retry fetch.RequestConfig error status code
	DefaultRetryHTTPCodes = []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, //nolint:lll
		http.StatusGatewayTimeout, http.StatusRequestTimeout}
	// DefaultHeaders defaults http headers
	DefaultHeaders = http.Header{
		"Accept":          {"*/*"},
		"Accept-Language": {"en-US,en;"},
		"User-Agent":      {"ski"},
	}
)

// Options The Fetch instance options
type Options struct {
	CharsetAutoDetect bool              `yaml:"charset-auto-detect"`
	MaxBodySize       int64             `yaml:"max-body-size"`
	RetryTimes        int               `yaml:"retry-times"`
	RetryHTTPCodes    []int             `yaml:"retry-http-codes"`
	Timeout           time.Duration     `yaml:"timeout"`
	Headers           http.Header       `yaml:"headers"`
	RoundTripper      http.RoundTripper `yaml:"-"`
	Jar               http.CookieJar    `yaml:"-"`
}

// NewFetch returns a new ski.Fetch instance
func NewFetch(opt Options) *Fetch {
	fetch := &Fetch{
		timeout:        opt.Timeout,
		retryHTTPCodes: opt.RetryHTTPCodes,
		headers:        opt.Headers,
		retryTimes:     uint(opt.RetryTimes),
	}

	fetch.charsetAutoDetect = opt.CharsetAutoDetect
	fetch.maxBodySize = opt.MaxBodySize
	if opt.Timeout == 0 {
		fetch.timeout = DefaultTimeout
	}
	if len(opt.RetryHTTPCodes) == 0 {
		fetch.retryHTTPCodes = DefaultRetryHTTPCodes
	}
	if len(fetch.headers) == 0 {
		fetch.headers = DefaultHeaders
	}

	transport := opt.RoundTripper
	if transport == nil {
		transport = DefaultRoundTripper()
	}

	fetch.Client = &http.Client{
		Transport: transport,
		Timeout:   fetch.timeout,
		Jar:       opt.Jar,
	}

	return fetch
}

// DefaultRoundTripper the fetch default RoundTripper
func DefaultRoundTripper() http.RoundTripper {
	t1 := &http.Transport{
		Proxy: ProxyFromRequest,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	_ = http2.ConfigureTransport(t1)
	return (*Decoder)(t1)
}

// Do sends an HTTP request and returns an HTTP response, following
// policy (such as redirects, cookies, auth) as configured on the
// client.
func (f *Fetch) Do(req *http.Request) (res *http.Response, err error) {
	for k, v := range f.headers {
		if _, ok := req.Header[k]; !ok {
			req.Header[k] = v
		}
	}

RETRY:
	times := uint(0)
	res, err = f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if slices.Contains(f.retryHTTPCodes, res.StatusCode) && times < f.retryTimes {
		times++
		goto RETRY
	}

	if f.maxBodySize > 0 {
		// Limit response body reading
		res.Body = &warpReadCloser{Reader: io.LimitReader(res.Body, f.maxBodySize), Closer: res.Body.Close}
	}

	if res.Request.Method != http.MethodHead {
		if res.ContentLength > 0 {
			if f.charsetAutoDetect {
				contentType := req.Header.Get("Content-Type")
				cr, err := charset.NewReader(res.Body, contentType)
				if err != nil {
					return nil, fmt.Errorf("charset detection error on content-type %s: %w", contentType, err)
				}
				res.Body = &warpReadCloser{Reader: cr, Closer: res.Body.Close}
			}
		}
	}

	return
}
