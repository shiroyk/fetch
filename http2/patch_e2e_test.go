// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"bufio"
	"bytes"
	"context"
	cryptotls "crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

// TestEndToEndOverPipe runs one HTTPS request through net/http against an upstream HTTP/2
// server, with both ends on an in-memory pipe. It is the only offline check that covers
// the whole fork wiring: net/http calls DialTLSContext, the uTLS handshake replaces the
// standard library one, hackTlsConn hands the result back as a *crypto/tls.Conn, and
// net/http routes the connection to TLSNextProto["h2"] instead of its bundled HTTP/2.
//
// The test also sniffs what the client puts on the wire, so a re-base that loses the
// Options plumbing fails here even if every site still compiles.
func TestEndToEndOverPipe(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	serverTLS := cryptotls.Server(serverPipe, &cryptotls.Config{
		Certificates: []cryptotls.Certificate{selfSignedCert(t)},
		NextProtos:   []string{NextProtoTLS},
	})
	// Sniff above the TLS layer so the captured bytes are HTTP/2 frames rather than
	// ciphertext.
	sniffed := &sniffingConn{Conn: serverTLS}
	go serveMinimalHTTP2(t, sniffed)

	t1 := &http.Transport{
		TLSClientConfig: &cryptotls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientPipe, nil
		},
	}
	_, err := ConfigureTransports(t1, Options{
		Settings:            goldenSettings,
		WindowSizeIncrement: goldenWindowSizeIncrement,
		PHeaderOrder:        goldenPHeaderOrder,
		HeaderOrder:         goldenHeaderOrder,
		// The handshake uses this config, not t1.TLSClientConfig; the test server
		// serves a throwaway certificate.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	require.NoError(t, err)

	client := &http.Client{Transport: t1, Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)

	require.NoError(t, err)
	req.Header = goldenHeader.Clone()
	resp, err := client.Do(req)

	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, "ok", string(body))

	wire := sniffed.snapshot()
	settings, headerFields := parseClientWire(t, wire)

	var got int
	for _, s := range settings {
		want := goldenSettings[got]
		assert.Equal(t, want.ID, s.ID)
		assert.Equal(t, want.Val, s.Val)
		got++
	}
	assert.Equal(t, len(goldenSettings), got)

	want := append(append([]string{}, goldenPHeaderOrder...), goldenHeaderOrder...)
	assert.Equal(t, want, headerFields)
}

// serveMinimalHTTP2 answers exactly one request with a 200 and a two byte body.
//
// net.Pipe has no buffer, and a write to it blocks until the peer reads. A real server can
// interleave writes with reads freely because the socket buffers, so the shape here has to
// compensate: the read loop never stops reading, and every write happens on its own
// goroutine. Otherwise the two peers deadlock while ACKing each other's SETTINGS.
func serveMinimalHTTP2(t *testing.T, conn net.Conn) {
	br := bufio.NewReader(conn)
	preface := make([]byte, len(ClientPreface))
	if _, err := io.ReadFull(br, preface); err != nil {
		return
	}
	fr := NewFramer(io.Discard, br)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	settingsSeen := make(chan struct{})
	headersSeen := make(chan *MetaHeadersFrame, 1)
	go func() {
		wfr := NewFramer(conn, bytes.NewReader(nil))
		<-settingsSeen
		if err := wfr.WriteSettings(); err != nil {
			return
		}
		headers := <-headersSeen
		var hbuf bytes.Buffer
		henc := hpack.NewEncoder(&hbuf)
		_ = henc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		_ = henc.WriteField(hpack.HeaderField{Name: "content-length", Value: "2"})
		if err := wfr.WriteHeaders(HeadersFrameParam{
			StreamID:      headers.StreamID,
			BlockFragment: hbuf.Bytes(),
			EndHeaders:    true,
		}); err != nil {
			return
		}
		_ = wfr.WriteData(headers.StreamID, true, []byte("ok"))
	}()

	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *SettingsFrame:
			if f.IsAck() {
				continue
			}
			select {
			case <-settingsSeen:
			default:
				close(settingsSeen)
			}
		case *MetaHeadersFrame:
			select {
			case headersSeen <- f:
			default:
			}
		}
	}
}

// parseClientWire skips the client preface and returns the first SETTINGS frame's entries
// together with the header field names of the first HEADERS frame, in wire order. Settings
// are copied while their frame is still current: the Framer reuses its read buffer, so a
// frame's payload is only valid until the next ReadFrame call.
func parseClientWire(t *testing.T, wire []byte) ([]Setting, []string) {
	t.Helper()
	if !bytes.HasPrefix(wire, []byte(ClientPreface)) {
		t.Fatalf("wire does not start with the client preface: %q", wire[:min(len(wire), 32)])
	}
	fr := NewFramer(io.Discard, bytes.NewReader(wire[len(ClientPreface):]))
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	var settings []Setting
	var names []string
	for range 32 {
		frame, err := fr.ReadFrame()
		if err != nil {
			break
		}
		switch f := frame.(type) {
		case *SettingsFrame:
			if settings == nil && !f.IsAck() {
				if err := f.ForeachSetting(func(s Setting) error {
					settings = append(settings, s)
					return nil
				}); err != nil {
					t.Fatalf("iterate SETTINGS: %v", err)
				}
			}
		case *MetaHeadersFrame:
			if names == nil {
				for _, hf := range f.Fields {
					names = append(names, hf.Name)
				}
			}
		}
		if settings != nil && names != nil {
			break
		}
	}
	require.NotNil(t, settings)
	require.NotNil(t, names)
	return settings, names
}

// sniffingConn records everything the peer reads, so the test can inspect the bytes the
// client actually sent.
type sniffingConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *sniffingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.buf.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *sniffingConn) snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}
