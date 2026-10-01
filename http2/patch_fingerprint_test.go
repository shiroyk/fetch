// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/shiroyk/fetch/http2/internal/httpcommon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file pins the fork's wire fingerprint without touching the network, so
// that re-basing the vendored http2 package onto a newer golang.org/x/net
// version fails fast in any environment. TestFingerPrint in patch_test.go
// remains the end-to-end counterpart; it needs EXTNET=1 and a live server.
//
// The golden values below are the ones observed for the profile defined here,
// which matches the profile used by TestFingerPrint.

const (
	goldenAkamaiFingerprint   = "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p"
	goldenWindowSizeIncrement = 15663105
)

var (
	goldenSettings = []Setting{
		{ID: SettingHeaderTableSize, Val: 65536},
		{ID: SettingEnablePush, Val: 0},
		{ID: SettingMaxConcurrentStreams, Val: 1000},
		{ID: SettingInitialWindowSize, Val: 6291456},
		{ID: SettingMaxHeaderListSize, Val: 262144},
	}

	goldenPHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}

	goldenHeaderOrder = []string{
		"sec-ch-ua", "sec-ch-ua-platform", "dnt",
		"user-agent", "accept", "sec-fetch-site",
		"sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"accept-encoding", "accept-language",
	}

	goldenHeader = http.Header{
		"Sec-Ch-Ua":          {`"Not.A/Brand";v="8", "Chromium";v="111", "Google Chrome";v="111"`},
		"Sec-Ch-Ua-Platform": {`"Windows"`},
		"Dnt":                {"1"},
		"User-Agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.111 Safari/537.36"},
		"Accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Sec-Fetch-Site":     {"none"},
		"Sec-Fetch-Mode":     {"navigate"},
		"Sec-Fetch-User":     {"?1"},
		"Sec-Fetch-Dest":     {"document"},
		"Accept-Encoding":    {"gzip, deflate, br"},
		"Accept-Language":    {"en,en_US;q=0.9"},
	}
)

// TestGoldenHeaderOrder checks that EncodeHeaders emits pseudo headers and
// regular headers in the order requested through Options, which is the header
// half of the akamai fingerprint.
func TestGoldenHeaderOrder(t *testing.T) {
	req := &http.Request{
		Method: "GET",
		Host:   "tls.peet.ws",
		URL:    &url.URL{Scheme: "https", Host: "tls.peet.ws", Path: "/api/all"},
		Header: goldenHeader,
	}

	var got []string
	_, err := httpcommon.EncodeHeaders(context.Background(), httpcommon.EncodeHeadersParam{
		Request: httpcommon.Request{
			Header: req.Header,
			URL:    req.URL,
			Host:   req.Host,
			Method: req.Method,
		},
		PHeaderOrder: goldenPHeaderOrder,
		HeaderOrder:  goldenHeaderOrder,
	}, func(name, value string) {
		got = append(got, name)
	})
	if err != nil {
		t.Fatalf("EncodeHeaders: %v", err)
	}

	want := append([]string{}, goldenPHeaderOrder...)
	want = append(want, goldenHeaderOrder...)

	assert.Equal(t, want, got)
}

// TestGoldenHeaderOrderDefault checks that dropping HeaderOrder restores the
// upstream behaviour, so a re-base cannot silently keep the fork's ordering
// semantics when the fork's plumbing is lost.
func TestGoldenHeaderOrderDefault(t *testing.T) {
	req := &http.Request{
		Method: "GET",
		Host:   "tls.peet.ws",
		URL:    &url.URL{Scheme: "https", Host: "tls.peet.ws", Path: "/api/all"},
		Header: goldenHeader,
	}

	var got []string
	_, err := httpcommon.EncodeHeaders(context.Background(), httpcommon.EncodeHeadersParam{
		Request: httpcommon.Request{
			Header: req.Header,
			URL:    req.URL,
			Host:   req.Host,
			Method: req.Method,
		},
	}, func(name, value string) {
		got = append(got, name)
	})
	if err != nil {
		t.Fatalf("EncodeHeaders: %v", err)
	}

	assert.Contains(t, strings.Join(got, ","), ":authority,:method,:path,:scheme")
}

// TestGoldenClientPrefaceFrames checks the frame half of the akamai
// fingerprint: the SETTINGS payload and the connection WINDOW_UPDATE increment
// that newClientConn puts on the wire, plus the absence of PRIORITY frames when
// Options.PriorityParams is nil.
func TestGoldenClientPrefaceFrames(t *testing.T) {
	tr := NewTransport(testTransportConfig{})
	tr.opt = Options{
		Settings:            goldenSettings,
		WindowSizeIncrement: goldenWindowSizeIncrement,
		PHeaderOrder:        goldenPHeaderOrder,
		HeaderOrder:         goldenHeaderOrder,
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// The server side of the pipe never speaks, so this call is expected to
		// fail once the test closes the connection.
		_, _ = tr.newClientConn(client, false, nil)
	}()

	br := bufio.NewReader(server)
	preface := make([]byte, len(ClientPreface))
	_, err := io.ReadFull(br, preface)
	require.NoError(t, err)
	assert.Equal(t, ClientPreface, string(preface))

	fr := NewFramer(io.Discard, br)

	frame, err := fr.ReadFrame()
	require.NoError(t, err)
	settings, ok := frame.(*SettingsFrame)
	assert.True(t, ok)
	var settingsPart []string
	err = settings.ForeachSetting(func(s Setting) error {
		settingsPart = append(settingsPart, fmt.Sprintf("%d:%d", s.ID, s.Val))
		return nil
	})
	require.NoError(t, err)

	frame, err = fr.ReadFrame()
	require.NoError(t, err)
	windowUpdate, ok := frame.(*WindowUpdateFrame)
	assert.True(t, ok)

	priorityPart := "0"
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	frame, err = fr.ReadFrame()
	require.Error(t, err)

	got := fmt.Sprintf("%s|%d|%s|%s",
		strings.Join(settingsPart, ";"),
		windowUpdate.Increment,
		priorityPart,
		strings.Join(pseudoHeaderCodes(goldenPHeaderOrder), ","),
	)
	assert.Equal(t, goldenAkamaiFingerprint, got)
}

// pseudoHeaderCodes maps HTTP/2 pseudo header names to the single letter codes
// used by the akamai fingerprint: m=:method, a=:authority, s=:scheme, p=:path.
func pseudoHeaderCodes(order []string) []string {
	codes := make([]string, 0, len(order))
	for _, h := range order {
		switch h {
		case ":method":
			codes = append(codes, "m")
		case ":authority":
			codes = append(codes, "a")
		case ":scheme":
			codes = append(codes, "s")
		case ":path":
			codes = append(codes, "p")
		default:
			codes = append(codes, h)
		}
	}
	return codes
}

// testTransportConfig is the minimum TransportConfig the vendored client needs to build a
// connection without a net/http Transport behind it.
type testTransportConfig struct{}

func (testTransportConfig) MaxHeaderListSize() int64             { return 0 }
func (testTransportConfig) MaxResponseHeaderBytes() int64        { return 0 }
func (testTransportConfig) DisableCompression() bool             { return false }
func (testTransportConfig) DisableKeepAlives() bool              { return false }
func (testTransportConfig) ExpectContinueTimeout() time.Duration { return 0 }
func (testTransportConfig) ResponseHeaderTimeout() time.Duration { return 0 }
func (testTransportConfig) IdleConnTimeout() time.Duration       { return 0 }
func (testTransportConfig) HTTP2Config() Config                  { return Config{} }

// TestHackTlsConn drives a real uTLS handshake over an in-memory pipe and checks the
// forged crypto/tls.Conn that net/http receives. This is the only offline coverage of the
// site that depends on unexported crypto/tls fields, so a Go upgrade that renames them
// fails here instead of at run time.
func TestHackTlsConn(t *testing.T) {
	t.Run("negotiated h2", func(t *testing.T) {
		uConn, forged := pipeHandshake(t, []string{NextProtoTLS})

		tlsConn, ok := forged.(*cryptotls.Conn)
		require.True(t, ok)
		state := tlsConn.ConnectionState()
		assert.NotEqual(t, state.ServerName, NextProtoTLS)
		nc := tlsConn.NetConn()
		assert.True(t, nc == net.Conn(uConn), "forged NetConn() = %#v, want the uTLS conn %#v", nc, uConn)
	})

	t.Run("other protocol is passed through", func(t *testing.T) {
		uConn, got := pipeHandshake(t, []string{"http/1.1"})
		assert.True(t, got == net.Conn(uConn), "hackTlsConn wrapped a conn that did not negotiate h2")
	})
}

// pipeHandshake runs a uTLS client handshake against a crypto/tls server over net.Pipe,
// offers the given ALPN protocols on both sides, and returns the client conn together with
// the result of hackTlsConn.
func pipeHandshake(t *testing.T, protos []string) (*tls.UConn, net.Conn) {
	t.Helper()
	clientPipe, serverPipe := net.Pipe()
	t.Cleanup(func() {
		clientPipe.Close()
		serverPipe.Close()
	})

	server := cryptotls.Server(serverPipe, &cryptotls.Config{
		Certificates: []cryptotls.Certificate{selfSignedCert(t)},
		NextProtos:   protos,
	})
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()

	uConn := tls.UClient(clientPipe, &tls.Config{
		ServerName:         "example.com",
		NextProtos:         protos,
		InsecureSkipVerify: true, // the pipe serves a throwaway certificate
	}, tls.HelloGolang)
	err := uConn.HandshakeContext(context.Background())
	require.NoError(t, err)
	err = <-serverErr
	require.NoError(t, err)
	return uConn, hackTlsConn(uConn)
}

func selfSignedCert(t *testing.T) cryptotls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return cryptotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
