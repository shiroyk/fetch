// This file is the fork's own code: it is not copied from the Go standard library.
// It holds the fingerprint options, the net/http integration, and the replacements for
// the vendored client functions the fork has to change.
//
// Maintenance rules: .agents/skills/http2-repatch/references/patch-manifest.json

package http2

import (
	"context"
	cryptotls "crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	tls "github.com/refraction-networking/utls"
)

const (
	defaultMaxStreams = 250 // TODO: make this 100 as the GFE seems to?

	// nextProtoUnencryptedHTTP2 is the TLSNextProto key net/http uses to hand a
	// cleartext HTTP/2 connection to an external implementation.
	nextProtoUnencryptedHTTP2 = "unencrypted_http2"
)

var hackField = map[string]uintptr{}

func init() {
	t := reflect.TypeOf(new(cryptotls.Conn)).Elem()
	for _, name := range []string{"conn", "config", "clientProtocol", "isHandshakeComplete"} {
		field, ok := t.FieldByName(name)
		if ok {
			hackField[name] = field.Offset
		}
	}
}

// hackTlsConn forges a *crypto/tls.Conn whose private fields point at the uTLS connection.
//
// net/http performs its own TLS handshake and then hands the result to the registered
// TLSNextProto["h2"] callback as a *crypto/tls.Conn. Because the fork wants that handshake
// to be a uTLS one, it dials through Transport.DialTLSContext and then has to hand
// net/http something it accepts. The forged value is only an envelope: net/http inspects
// clientProtocol for ALPN and then calls NetConn(), which returns the uTLS conn stored in
// the conn field.
//
// The field names and their layout are unexported details of the standard library. If any
// of them disappears or changes type, this site is BROKEN rather than something to work
// around with a different cast.
func hackTlsConn(uConn *tls.UConn) net.Conn {
	state := uConn.ConnectionState()
	if state.NegotiatedProtocol != NextProtoTLS {
		return uConn
	}
	ret := new(cryptotls.Conn)

	for field, offset := range hackField {
		ptr := unsafe.Add(unsafe.Pointer(ret), offset)
		switch field {
		case "conn":
			*(*net.Conn)(ptr) = uConn
		case "config":
			*(**cryptotls.Config)(ptr) = new(cryptotls.Config)
		case "clientProtocol":
			*(*string)(ptr) = state.NegotiatedProtocol
		case "isHandshakeComplete":
			(*atomic.Bool)(ptr).Store(true)
		}
	}
	return ret
}

type Options struct {
	// HeaderOrder is for ResponseWriter.Header map keys
	// that, if present, defines a header order that will be used to
	// write the headers onto wire. The order of the slice defined how the headers
	// will be sorted. A defined Key goes before an undefined Key.
	//
	// This is the only way to specify some order, because maps don't
	// have a stable iteration order. If no order is given, headers will
	// be sorted lexicographically.
	//
	// According to RFC2616 it is good practice to send general-header fields
	// first, followed by request-header or response-header fields and ending
	// with entity-header fields.
	HeaderOrder []string

	// PHeaderOrder is for setting http2 pseudo header order.
	// If is nil it will use regular GoLang header order.
	// Valid fields are :authority, :method, :path, :scheme
	PHeaderOrder []string

	// Settings frame, the client informs the server about its HTTP/2 preferences.
	// if nil, will use default settings
	Settings []Setting

	// WindowSizeIncrement optionally specifies an upper limit for the
	// WINDOW_UPDATE frame. If zero, the default value of 2^30 is used.
	WindowSizeIncrement uint32

	// PriorityParams specifies the sender-advised priority of a stream.
	// if nil, will not send.
	PriorityParams map[uint32]PriorityParam

	// GetTlsClientHelloSpec returns the TLS spec to use with
	// tls.UClient.
	// If nil, the default configuration is used.
	GetTlsClientHelloSpec func() *tls.ClientHelloSpec

	// TLSClientConfig is the uTLS configuration used for the handshake. The vendored
	// transport has no TLS config of its own, so the fork carries it here.
	TLSClientConfig *tls.Config

	// dialContext opens the plain TCP connection that the uTLS handshake runs on.
	// It is filled in from the net/http Transport and is not user configurable.
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// transportConfig adapts the net/http Transport the fork is installed on to the vendored
// client's TransportConfig interface.
type transportConfig struct {
	t1 *http.Transport
}

func (c transportConfig) MaxHeaderListSize() int64 {
	// net/http has no equivalent of the old x/net MaxHeaderListSize; the header list
	// limit comes from MaxResponseHeaderBytes below.
	return 0
}

func (c transportConfig) MaxResponseHeaderBytes() int64 {
	if c.t1 == nil {
		return 0
	}
	return c.t1.MaxResponseHeaderBytes
}

func (c transportConfig) DisableCompression() bool {
	return c.t1 == nil || c.t1.DisableCompression
}

func (c transportConfig) DisableKeepAlives() bool {
	return c.t1 != nil && c.t1.DisableKeepAlives
}

func (c transportConfig) ExpectContinueTimeout() time.Duration {
	if c.t1 == nil {
		return 0
	}
	return c.t1.ExpectContinueTimeout
}

func (c transportConfig) ResponseHeaderTimeout() time.Duration {
	if c.t1 == nil {
		return 0
	}
	return c.t1.ResponseHeaderTimeout
}

func (c transportConfig) IdleConnTimeout() time.Duration {
	if c.t1 == nil {
		return 0
	}
	return c.t1.IdleConnTimeout
}

// HTTP2Config reports the HTTP/2 settings the caller put on the net/http Transport.
// Config and http.HTTP2Config are kept field-for-field identical upstream.
func (c transportConfig) HTTP2Config() Config {
	if c.t1 == nil || c.t1.HTTP2 == nil {
		return Config{}
	}
	return Config(*c.t1.HTTP2)
}

var zeroDialer net.Dialer

func dialContextFrom(t1 *http.Transport) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if t1 != nil && t1.DialContext != nil {
		return t1.DialContext
	}
	return zeroDialer.DialContext
}

// ConfigureTransport configures a net/http HTTP/1 Transport to use HTTP/2.
// It returns an error if t1 has already been HTTP/2-enabled.
//
// Use ConfigureTransports instead to configure the HTTP/2 Transport.
func ConfigureTransport(t1 *http.Transport, opt ...Options) error {
	_, err := ConfigureTransports(t1, opt...)
	return err
}

// ConfigureTransports configures a net/http HTTP/1 Transport to use HTTP/2.
// It returns a new HTTP/2 Transport for further configuration.
// It returns an error if t1 has already been HTTP/2-enabled.
func ConfigureTransports(t1 *http.Transport, opt ...Options) (*Transport, error) {
	return configureTransports(t1, opt...)
}

func configureTransports(t1 *http.Transport, opt ...Options) (*Transport, error) {
	t2 := NewTransport(transportConfig{t1: t1})
	if len(opt) > 0 {
		t2.opt = opt[0]
	}
	if t2.opt.dialContext == nil {
		t2.opt.dialContext = dialContextFrom(t1)
	}

	// Every h2 dial goes through uTLS: net/http must not run its own handshake.
	t1.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		conn, err := t2.dialTLSWithContext(ctx, network, addr, t2.newTLSConfig(host))
		if err != nil {
			return nil, err
		}
		// Hand net/http the forged crypto/tls.Conn that wraps the uTLS conn.
		return hackTlsConn(conn), nil
	}
	if err := registerHTTPSProtocol(t1, noDialH2RoundTripper{t: t2}); err != nil {
		return nil, err
	}
	if t1.TLSClientConfig == nil {
		t1.TLSClientConfig = new(cryptotls.Config)
	}
	if !slices.Contains(t1.TLSClientConfig.NextProtos, "h2") {
		t1.TLSClientConfig.NextProtos = append([]string{"h2"}, t1.TLSClientConfig.NextProtos...)
	}
	if !slices.Contains(t1.TLSClientConfig.NextProtos, "http/1.1") {
		t1.TLSClientConfig.NextProtos = append(t1.TLSClientConfig.NextProtos, "http/1.1")
	}
	upgradeFn := func(scheme, authority string, c net.Conn) http.RoundTripper {
		addr := authorityAddr(scheme, authority)
		if used, err := t2.connPool.addConnIfNeeded(addr, t2, c); err != nil {
			go c.Close()
			return errRoundTripper{err}
		} else if !used {
			// Turns out we don't need this c.
			// For example, two goroutines made requests to the same host
			// at the same time, both kicking off TCP dials. (since protocol
			// was unknown)
			go c.Close()
		}
		// The RoundTripper attached to a connection net/http already handed over must
		// report ErrNoCachedConn unchanged: net/http retries a request with a fresh dial
		// when it recognises that error. Only the RegisterProtocol entry point above
		// converts it, because there the contract is http.ErrSkipAltProtocol.
		return h2RoundTripper{t: t2}
	}
	if t1.TLSNextProto == nil {
		t1.TLSNextProto = make(map[string]func(string, *cryptotls.Conn) http.RoundTripper)
	}
	t1.TLSNextProto[NextProtoTLS] = func(authority string, c *cryptotls.Conn) http.RoundTripper {
		// get the uTLS conn back out of the forged crypto/tls.Conn
		return upgradeFn("https", authority, c.NetConn())
	}
	// The "unencrypted_http2" TLSNextProto key is used to pass off non-TLS HTTP/2 conns.
	t1.TLSNextProto[nextProtoUnencryptedHTTP2] = func(authority string, c *cryptotls.Conn) http.RoundTripper {
		return upgradeFn("http", authority, c.NetConn())
	}
	return t2, nil
}

// registerHTTPSProtocol calls Transport.RegisterProtocol, which panics on a duplicate
// registration, and reports that as an error.
func registerHTTPSProtocol(t *http.Transport, rt http.RoundTripper) (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()
	t.RegisterProtocol("https", rt)
	return nil
}

// noDialH2RoundTripper implements http.RoundTripper by handing the request to the vendored
// client. It never dials: net/http dials and pushes the connection into the pool.
type noDialH2RoundTripper struct {
	t *Transport
}

func (rt noDialH2RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := rt.t.roundTripHTTP(req)
	if err == errClientConnUnusable || err == errClientConnGotGoAway || isNoCachedConnError(err) {
		return nil, http.ErrSkipAltProtocol
	}
	return res, err
}

// h2RoundTripper serves the requests net/http routes to a connection it already handed to
// the fork through TLSNextProto. Unlike noDialH2RoundTripper it never converts errors into
// http.ErrSkipAltProtocol: that sentinel is only meaningful where net/http is choosing
// between the registered protocol and its own dial path, not once a connection exists.
type h2RoundTripper struct {
	t *Transport
}

func (rt h2RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.t.roundTripHTTP(req)
}

type errRoundTripper struct{ err error }

func (rt errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, rt.err }
func (rt errRoundTripper) RoundTripErr() error                             { return rt.err }

// roundTripHTTP runs one *http.Request through the vendored client, which speaks its own
// ClientRequest/ClientResponse types to stay independent of net/http.
func (t *Transport) roundTripHTTP(req *http.Request) (*http.Response, error) {
	res, err := t.RoundTripOpt(clientRequestFromRequest(req), RoundTripOpt{})
	if err != nil {
		return nil, err
	}
	return httpResponseFromClientResponse(req, res), nil
}

func clientRequestFromRequest(req *http.Request) *ClientRequest {
	return &ClientRequest{
		Context:       req.Context(),
		Method:        req.Method,
		URL:           req.URL,
		Header:        Header(req.Header),
		Trailer:       Header(req.Trailer),
		Body:          req.Body,
		Host:          req.Host,
		GetBody:       req.GetBody,
		ContentLength: req.ContentLength,
		Close:         req.Close,
	}
}

func httpResponseFromClientResponse(req *http.Request, res *ClientResponse) *http.Response {
	return &http.Response{
		Status:        res.Status,
		StatusCode:    res.StatusCode,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        http.Header(res.Header),
		Trailer:       http.Header(res.Trailer),
		Body:          res.Body,
		ContentLength: res.ContentLength,
		Uncompressed:  res.Uncompressed,
		Request:       req,
		TLS:           res.TLS,
	}
}

// foreachHeaderElement splits v according to the "#rule" construction
// in RFC 7230 section 7 and calls fn for each non-empty element.
func foreachHeaderElement(v string, fn func(string)) {
	v = textproto.TrimString(v)
	if v == "" {
		return
	}
	if !strings.Contains(v, ",") {
		fn(v)
		return
	}
	for _, f := range strings.Split(v, ",") {
		if f = textproto.TrimString(f); f != "" {
			fn(f)
		}
	}
}

var _ = io.Discard
