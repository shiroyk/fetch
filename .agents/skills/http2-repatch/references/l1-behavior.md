# L1 — behaviour sites

Read this when a site with `layer: L1` is `SHIFTED` or `BROKEN`, or when deciding whether
an upstream change actually threatens the fingerprint.

## What L1 must preserve

1. **Every h2 dial goes through uTLS.** `ConfigureTransport` sets `t1.DialTLSContext`, so
   `net/http` never runs its own handshake.
2. **The ClientHello is caller-controlled.** `Options.GetTlsClientHelloSpec` produces a
   `*utls.ClientHelloSpec`; nil means `HelloGolang`.
3. **The connection preface is caller-controlled.** SETTINGS entries reach the wire in the
   caller's order, the connection WINDOW_UPDATE uses `Options.WindowSizeIncrement` when
   non-zero, and each `Options.PriorityParams` entry becomes one PRIORITY frame.
4. **Header order is caller-controlled.** `Options.PHeaderOrder` orders pseudo headers,
   `Options.HeaderOrder` orders regular headers, and neither set means upstream behaviour.
5. **The forged conn keeps net/http routing to the fork.** `hackTlsConn` turns the uTLS
   conn into a `*crypto/tls.Conn` so `TLSNextProto["h2"]` is called, and both the h2 and
   `unencrypted_http2` entries route through `upgradeFn`.
6. **The fork transport is built through `NewTransport`.** Building `&Transport{...}` by
   hand leaves the connection pool nil and panics on the first request.

## Where the behaviour sites live

The standard library package keeps the whole client in `transport.go`, so the three edited
functions are all there: `dialTLSWithContext` (uTLS), `newClientConn` (fingerprint frames)
and `encodeRequestHeaders` (header order). Everything with no upstream counterpart lives in
the fork-owned `patch.go`.

## Re-anchoring notes

- Upstream moves these functions between files between releases (`v0.56` split some of them
  out of `transport.go`, `v0.59` moved them back). Edit the file that owns the function in
  the target toolchain and move the `// fork:` marker with it.
- The adapter layer follows upstream's *types*: if `ClientRequest`, `ClientResponse` or
  `TransportConfig` gains a field or method, `patch.go` must mirror it. A missing field
  usually shows up as a silent behaviour change, not a compile error, so re-read the two
  structs on every re-base.
- `TransportConfig` is where caller settings arrive. If upstream adds a method, the fork's
  `transportConfig` needs it too; `Config` and `http.HTTP2Config` are documented as
  field-for-field identical, so the direct conversion stays valid only while that holds.
- The handshake config comes from `Options.TLSClientConfig`, because the vendored Transport
  has no TLS fields. The test uses this to trust the pipe server's throwaway certificate.
- `hackTlsConn` depends on unexported `crypto/tls.Conn` fields, and on `net/http` still
  calling `NetConn()` on the conn it hands to `TLSNextProto`. Both are verified offline by
  `TestHackTlsConn` and `TestEndToEndOverPipe`.

## Behavioural checks

| Check | How |
| --- | --- |
| SETTINGS payload and order | `TestGoldenClientPrefaceFrames` |
| WINDOW_UPDATE increment | `TestGoldenClientPrefaceFrames` |
| No PRIORITY frames when `PriorityParams` is nil | `TestGoldenClientPrefaceFrames` |
| Pseudo header order | `TestGoldenHeaderOrder` |
| Header order, and upstream fallback | `TestGoldenHeaderOrder`, `TestGoldenHeaderOrderDefault` |
| Forged conn shape | `TestHackTlsConn` |
| net/http routing and options on the wire | `TestEndToEndOverPipe` |
| Real handshake fingerprint | `EXTNET=1 go test ./http2/ -run TestFingerPrint` |

## When to stop

Stop and report `BROKEN` if the uTLS conn can no longer be delivered through
`TLSNextProto`, if the unexported `crypto/tls.Conn` fields disappear, or if upstream starts
providing fingerprint control itself. Do not replace the uTLS path with a lower-fidelity
fallback: the fork exists for the fingerprint, so a silent downgrade is worse than a failed
re-base.
