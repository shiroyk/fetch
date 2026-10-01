# What the patch does, and why

This document explains the deltas between `http2/` and the Go toolchain's
`net/http/internal/http2` at the base recorded in `patch-manifest.json`. Read it before
changing a site whose verdict is not `INTACT`; the reasons matter more than the mechanics,
because upstream refactors move the mechanics while the reasons stay fixed.

## Goal

`github.com/shiroyk/fetch` wants the wire-visible fingerprint of an HTTP/2 request to be
chosen by the caller: TLS ClientHello (through uTLS), SETTINGS values, the connection
WINDOW_UPDATE increment, PRIORITY frames, and header order. Neither `net/http` nor the
package it delegates to allows any of that: the client hardcodes its ClientHello via
`crypto/tls`, builds its own SETTINGS list, and emits pseudo headers in a fixed order.

## Why the standard library package

As of Go 1.27 `net/http/internal/http2` is the source of truth for the Go HTTP/2
implementation; `golang.org/x/net/http2` documents itself as receiving only critical fixes.
Earlier the fork vendored x/net's copy, which also selected between a legacy and a
"wrapping" implementation with build tags. The standard library copy has neither problem:
it is the implementation `net/http` itself uses, and there is no build-tag split. The price
is that the base is now a toolchain rather than a module version.

`net/http` never uses an external copy of its own engine — `RegisterProtocol("http/2", cfg)`
only lets an external config influence dialing and configuration, not the implementation.
The fork therefore installs itself on the caller's `http.Transport` through
`TLSNextProto["h2"]`, exactly as the old x/net transport did.

## Delta summary

| Upstream file | Change in the fork |
| --- | --- |
| `api.go` | `net/http/internal` sentinels replaced with `http` equivalents, `NoBody`/`LocalAddrContextKey` initialised locally, server-facing types dropped. |
| `config.go` | `configFromServer` dropped; `Config` stays identical to `http.HTTP2Config`. |
| `frame.go` | `internal/httpsfv` import rewritten to the fork's copy. |
| `transport.go` | `Transport` gains `opt Options`; `dialTLSWithContext` rewritten on uTLS; `newClientConn` takes SETTINGS/WINDOW_UPDATE/PRIORITY from Options and tolerates a non-h2 protocol; `encodeRequestHeaders` carries Options. |
| `internal/httpcommon/httpcommon.go` | `HeaderOrder`/`PHeaderOrder` added to `EncodeHeadersParam`; pseudo-header and regular-header emission made order-aware; server-side `NewServerRequest` dropped. |
| `internal/httpcommon/sorts.go` | New file: `headerSorter`, `sortedKeyValues`, `sortedKeyValuesBy`. |
| `patch.go` | New file: `Options`, `transportConfig`, the `*http.Request` adapter, `ConfigureTransport(s)`, `hackTlsConn`, `unencryptedNetConnFromTLSConn`, `defaultMaxStreams`, `foreachHeaderElement`. |
| everything else | Byte-identical to the toolchain's copy, or deliberately not vendored. |

## Why each site exists

### The adapter layer is fork-owned

The standard library package cannot import `net/http` (that is the import cycle it exists
to avoid), so it speaks its own `ClientRequest`/`ClientResponse` types and reads caller
configuration through a `TransportConfig` interface. `net/http`'s own adapter lives in
unexported code in `src/net/http/http2.go`. A fork outside the standard library has to
write that layer itself: `transportConfig` (delegating to the caller's `http.Transport`) and
`clientRequestFromRequest` / `httpResponseFromClientResponse`.

The fork also has to build its transport through `NewTransport`, which is what creates the
connection pool; a hand-built `&Transport{...}` panics on the first request.

### `hackTlsConn` exists because `net/http` decides the protocol, not this package

`net/http`'s `Transport` dials, and — because `DialTLSContext` is set — calls the fork for
the TLS handshake. It then insists on a `*crypto/tls.Conn` for the `TLSNextProto["h2"]`
callback. `hackTlsConn` manufactures one: it allocates a zero `crypto/tls.Conn` and, using
field offsets collected by reflection, writes the uTLS connection into `conn`, an empty
`crypto/tls.Config` into `config`, the negotiated ALPN into `clientProtocol`, and true into
`isHandshakeComplete`. The forged value is only an envelope: `net/http` inspects it for
protocol negotiation and then calls `(*tls.Conn).NetConn()`, which returns the uTLS conn.

Consequences worth remembering:

- The offsets are unexported implementation details. A field rename, removal, or type change
  breaks the trick; that is a `BROKEN` verdict, not something to paper over.
- `isHandshakeComplete` is an `atomic.Bool`; assigning a value copies `noCopy` and fails
  `go vet`, so it is set with `Store`.
- This site disappears only if the fork stops using `TLSNextProto` and owns the HTTPS path
  itself — which would mean reimplementing proxy CONNECT, since `net/http` currently does
  that before the handshake.

### `dialTLSWithContext` and `newClientConn` are where the fingerprint lands

`dialTLSWithContext` wraps the dialed conn in `tls.UClient` under either `HelloCustom` plus
`ApplyPreset(spec)` or `HelloGolang`. `newClientConn` replaces the SETTINGS list and the
connection WINDOW_UPDATE with the caller's values, writes one PRIORITY frame per entry, and
returns early instead of failing when the negotiated ALPN is not `h2`.

Both stay in place in the vendored file with a `// fork:` marker; there is no overriding in
Go, and keeping the rest of the function intact is what makes the next re-base a diff
instead of a rewrite.

### Header order is patched inside `internal/httpcommon`

The akamai fingerprint includes the order of the pseudo headers and of the regular headers.
Header emission lives in `net/http/internal/httpcommon`, which the fork cannot import, so
the package is copied next to the HTTP/2 copy with its import path rewritten, and the
ordering behaviour is added there. Upstream's `httpcommon.go` also carries server-side
decoding, which the client-only subset does not need.

## Fragility register

| Trigger | Effect |
| --- | --- |
| `crypto/tls.Conn` private fields renamed, removed, or retyped | `site-hack-tls-conn` is BROKEN; `net/http` will no longer accept the uTLS conn. |
| `net/http` stops calling `NetConn()` on the `TLSNextProto` conn, or stops routing h2 there | `site-configure-transports` is BROKEN. |
| `ClientRequest`, `ClientResponse` or `TransportConfig` changes shape | `site-http-request-adapter` / `site-transport-config-adapter` need the new fields; symptoms are silent, not compile errors. |
| `Config` stops mirroring `http.HTTP2Config` field-for-field | the direct conversion in `transportConfig.HTTP2Config` must be replaced with explicit mapping. |
| `newClientConn` or `dialTLSWithContext` moves or is split | re-anchor the markers; usually `SHIFTED`. |
| `internal/httpcommon` splits back into several files or is renamed | the copy rule and `site-httpcommon-*` move with it. |
| Upstream starts using another `net/http/internal` symbol | `site-internal-import-rewrite`: map it to the exported `http` equivalent or localise it. |
| Upstream starts supporting fingerprint control itself | every L1 site becomes a candidate for deletion; stop and ask rather than keeping a divergent fork by default. |

## Verification contract

- Frames: `TestGoldenClientPrefaceFrames` reads the preface, SETTINGS and WINDOW_UPDATE that
  `newClientConn` emits on an in-memory pipe.
- Headers: `TestGoldenHeaderOrder` asserts the emitted name sequence for the same profile.
- Forgery: `TestHackTlsConn` runs a real uTLS handshake over a pipe and checks the forged
  `crypto/tls.Conn`, so a Go release that renames the private fields fails offline.
- Wiring: `TestEndToEndOverPipe` drives one HTTPS request through `net/http` against a
  hand-written HTTP/2 responder over a pipe, asserting the 200 response plus the SETTINGS
  and header order that reached the wire.

`TestFingerPrint` in `patch_test.go` remains the end-to-end check against a live server and
needs `EXTNET=1`. A re-base is only complete when T1, T2 and T4 pass and the report gives
one verdict per manifest site.
