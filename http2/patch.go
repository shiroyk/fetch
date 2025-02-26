package http2

import (
	"bufio"
	"context"
	cryptotls "crypto/tls"
	"net"
	"net/http"
	"net/textproto"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2/hpack"
)

const (
	defaultMaxStreams = 250 // TODO: make this 100 as the GFE seems to?
)

var hackField = map[string]uintptr{}
var done = atomic.Bool{}

func init() {
	done.Store(true)
	t := reflect.TypeOf(new(cryptotls.Conn)).Elem()
	for _, name := range []string{"conn", "config", "clientProtocol", "isHandshakeComplete"} {
		field, ok := t.FieldByName(name)
		if ok {
			hackField[name] = field.Offset
		}
	}
}

// hackTlsConn make a hack, set private field
func hackTlsConn(uConn *tls.UConn) net.Conn {
	state := uConn.ConnectionState()
	if state.NegotiatedProtocol != NextProtoTLS {
		return uConn
	}
	ret := new(cryptotls.Conn)

	for field, offset := range hackField {
		ptr := unsafe.Pointer(uintptr(unsafe.Pointer(ret)) + offset)
		switch field {
		case "conn":
			*(*net.Conn)(ptr) = uConn
		case "config":
			*(**cryptotls.Config)(ptr) = &cryptotls.Config{}
		case "clientProtocol":
			*(*string)(ptr) = state.NegotiatedProtocol
		case "isHandshakeComplete":
			*(*atomic.Bool)(ptr) = done
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
	connPool := new(clientConnPool)
	t2 := &Transport{
		AllowHTTP: true,
		ConnPool:  noDialClientConnPool{connPool},
		t1:        t1,
	}
	if len(opt) > 0 {
		t2.opt = opt[0]
	}
	connPool.t = t2
	t1.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		conn, err := t2.dialTLSWithContext(ctx, network, addr, t2.newTLSConfig(host))
		if err != nil {
			return nil, err
		}
		// set the utls.Conn to cryptotls.NetConn
		return hackTlsConn(conn), nil
	}
	if err := registerHTTPSProtocol(t1, noDialH2RoundTripper{t2}); err != nil {
		return nil, err
	}
	if t1.TLSClientConfig == nil {
		t1.TLSClientConfig = new(cryptotls.Config)
	}
	if !strSliceContains(t1.TLSClientConfig.NextProtos, "h2") {
		t1.TLSClientConfig.NextProtos = append([]string{"h2"}, t1.TLSClientConfig.NextProtos...)
	}
	if !strSliceContains(t1.TLSClientConfig.NextProtos, "http/1.1") {
		t1.TLSClientConfig.NextProtos = append(t1.TLSClientConfig.NextProtos, "http/1.1")
	}
	upgradeFn := func(scheme, authority string, c net.Conn) http.RoundTripper {
		addr := authorityAddr(scheme, authority)
		if used, err := connPool.addConnIfNeeded(addr, t2, c); err != nil {
			go c.Close()
			return erringRoundTripper{err}
		} else if !used {
			// Turns out we don't need this c.
			// For example, two goroutines made requests to the same host
			// at the same time, both kicking off TCP dials. (since protocol
			// was unknown)
			go c.Close()
		}
		if scheme == "http" {
			return (*unencryptedTransport)(t2)
		}
		return t2
	}
	if t1.TLSNextProto == nil {
		t1.TLSNextProto = make(map[string]func(string, *cryptotls.Conn) http.RoundTripper)
	}
	t1.TLSNextProto[NextProtoTLS] = func(authority string, c *cryptotls.Conn) http.RoundTripper {
		// get the utls.Conn
		return upgradeFn("https", authority, c.NetConn())
	}
	// The "unencrypted_http2" TLSNextProto key is used to pass off non-TLS HTTP/2 conns.
	t1.TLSNextProto[nextProtoUnencryptedHTTP2] = func(authority string, c *cryptotls.Conn) http.RoundTripper {
		nc, err := unencryptedNetConnFromTLSConn(c.NetConn())
		if err != nil {
			go c.Close()
			return erringRoundTripper{err}
		}
		return upgradeFn("http", authority, nc)
	}
	return t2, nil
}

var zeroDialer net.Dialer

// dialTLSWithContext uses tls.Dialer, added in Go 1.15, to open a TLS
// connection.
func (t *Transport) dialTLSWithContext(ctx context.Context, network, addr string, cfg *tls.Config) (tlsConn *tls.UConn, err error) {
	var conn net.Conn
	if t.t1 != nil && t.t1.DialContext != nil {
		conn, err = t.t1.DialContext(ctx, network, addr)
	} else {
		conn, err = zeroDialer.DialContext(ctx, network, addr)
	}

	if err != nil {
		return
	}

	if t.opt.GetTlsClientHelloSpec != nil {
		tlsConn = tls.UClient(conn, cfg, tls.HelloCustom)
		if err = tlsConn.ApplyPreset(t.opt.GetTlsClientHelloSpec()); err != nil {
			go conn.Close()
			return
		}
	} else {
		tlsConn = tls.UClient(conn, cfg, tls.HelloGolang)
	}

	if err = tlsConn.HandshakeContext(ctx); err != nil {
		go conn.Close()
		return
	}
	return
}

func (t *Transport) newClientConn(c net.Conn, singleUse bool) (*ClientConn, error) {
	conf := configFromTransport(t)
	cc := &ClientConn{
		t:                           t,
		tconn:                       c,
		readerDone:                  make(chan struct{}),
		nextStreamID:                1,
		maxFrameSize:                16 << 10, // spec default
		initialWindowSize:           65535,    // spec default
		initialStreamRecvWindowSize: conf.MaxUploadBufferPerStream,
		maxConcurrentStreams:        initialMaxConcurrentStreams, // "infinite", per spec. Use a smaller value until we have received server settings.
		peerMaxHeaderListSize:       0xffffffffffffffff,          // "infinite", per spec. Use 2^64-1 instead.
		streams:                     make(map[uint32]*clientStream),
		singleUse:                   singleUse,
		seenSettingsChan:            make(chan struct{}),
		wantSettingsAck:             true,
		readIdleTimeout:             conf.SendPingTimeout,
		pingTimeout:                 conf.PingTimeout,
		pings:                       make(map[[8]byte]chan struct{}),
		reqHeaderMu:                 make(chan struct{}, 1),
		lastActive:                  t.now(),
	}

	// Start the idle timer after the connection is fully initialized.
	if d := t.idleConnTimeout(); d != 0 {
		cc.idleTimeout = d
		cc.idleTimer = t.afterFunc(d, cc.onIdleTimeout)
	}

	var group synctestGroupInterface
	if t.transportTestHooks != nil {
		t.markNewGoroutine()
		t.transportTestHooks.newclientconn(cc)
		c = cc.tconn
		group = t.group
	}

	cc.cond = sync.NewCond(&cc.mu)
	cc.flow.add(int32(initialWindowSize))

	// TODO: adjust this writer size to account for frame size +
	// MTU + crypto/tls record padding.
	cc.bw = bufio.NewWriter(stickyErrWriter{
		group:   group,
		conn:    c,
		timeout: conf.WriteByteTimeout,
		err:     &cc.werr,
	})
	cc.br = bufio.NewReader(c)
	cc.fr = NewFramer(cc.bw, cc.br)
	cc.fr.SetMaxReadFrameSize(conf.MaxReadFrameSize)
	if t.CountError != nil {
		cc.fr.countError = t.CountError
	}

	if t.AllowHTTP {
		cc.nextStreamID = 3
	}

	cc.henc = hpack.NewEncoder(&cc.hbuf)
	cc.henc.SetMaxDynamicTableSizeLimit(conf.MaxEncoderHeaderTableSize)
	cc.peerMaxHeaderTableSize = initialHeaderTableSize

	if cs, ok := c.(connectionStater); ok {
		state := cs.ConnectionState()
		//cc.tlsState = state
		// if not HTTP/2
		if state.NegotiatedProtocol != NextProtoTLS {
			return cc, nil
		}
	}

	maxHeaderTableSize := conf.MaxDecoderHeaderTableSize
	var settings []Setting
	if len(t.opt.Settings) == 0 {
		settings = []Setting{
			{ID: SettingEnablePush, Val: 0},
			{ID: SettingInitialWindowSize, Val: uint32(cc.initialStreamRecvWindowSize)},
		}
		settings = append(settings, Setting{ID: SettingMaxFrameSize, Val: conf.MaxReadFrameSize})
		if max := t.maxHeaderListSize(); max != 0 {
			settings = append(settings, Setting{ID: SettingMaxHeaderListSize, Val: max})
		}
		if maxHeaderTableSize != initialHeaderTableSize {
			settings = append(settings, Setting{ID: SettingHeaderTableSize, Val: maxHeaderTableSize})
		}
	} else {
		settings = t.opt.Settings
		settingVal := make([]uint32, 7)
		for _, setting := range settings {
			if err := setting.Valid(); err != nil {
				return nil, err
			}
			settingVal[setting.ID] = setting.Val
		}
		if v := settingVal[SettingHeaderTableSize]; v > 0 {
			t.MaxEncoderHeaderTableSize = v
			t.MaxDecoderHeaderTableSize = v
			maxHeaderTableSize = v
		}
		if v := settingVal[SettingMaxConcurrentStreams]; v > 0 {
			cc.maxConcurrentStreams = v
		}
		if v := settingVal[SettingInitialWindowSize]; v > 0 {
			cc.initialWindowSize = v
		}
		if v := settingVal[SettingMaxFrameSize]; v > 0 {
			t.MaxReadFrameSize = v
			cc.maxFrameSize = v
		}
		if v := settingVal[SettingMaxHeaderListSize]; v > 0 {
			t.MaxHeaderListSize = v
		}
	}

	cc.fr.ReadMetaHeaders = hpack.NewDecoder(maxHeaderTableSize, nil)
	cc.fr.MaxHeaderListSize = t.maxHeaderListSize()

	cc.bw.Write(clientPreface)
	cc.fr.WriteSettings(settings...)
	if t.opt.WindowSizeIncrement > 0 {
		cc.fr.WriteWindowUpdate(0, t.opt.WindowSizeIncrement)
		cc.inflow.init(int32(t.opt.WindowSizeIncrement + initialWindowSize))
	} else {
		cc.fr.WriteWindowUpdate(0, transportDefaultConnFlow)
		cc.inflow.init(transportDefaultConnFlow + initialWindowSize)
	}
	if len(t.opt.PriorityParams) > 0 {
		for id, frame := range t.opt.PriorityParams {
			cc.fr.WritePriority(id, frame)
		}
	}
	cc.bw.Flush()
	if cc.werr != nil {
		cc.Close()
		return nil, cc.werr
	}

	// Start the idle timer after the connection is fully initialized.
	if d := t.idleConnTimeout(); d != 0 {
		cc.idleTimeout = d
		cc.idleTimer = t.afterFunc(d, cc.onIdleTimeout)
	}

	go cc.readLoop()
	return cc, nil
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
