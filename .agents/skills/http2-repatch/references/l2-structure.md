# L2 — structural sites

These sites are about *which* code exists in `http2/` and *how it is wired*, not about
behaviour. They break a re-base with compile errors rather than failing tests, so run
`scripts/subset-check.sh` first.

## Where upstream lives

- `upstream_root` in `patch-manifest.json` is relative to `$(go env GOROOT)`:
  `src/net/http/internal`. The copy source is that plus `http2`.
- As of Go 1.27 the standard library package is the source of truth; `golang.org/x/net/http2`
  only receives critical fixes. Re-basing therefore means re-copying from a toolchain, so
  `base_go` and `min_go` move together with the copy.
- `golang.org/x/net` stays a module dependency for `hpack`, `httpguts` and `idna`, so a
  dependency bump is a separate change from a re-base.
- `scripts/subset-check.sh` warns when the toolchain in use is not `base_go` and then
  compares against the toolchain that is actually installed.

## File selection

- The allowlist in `patch-manifest.json` is the source of truth. Add a file only when the
  package fails to compile without it, and record it.
- `scripts/subset-check.sh` reports allowlist entries missing upstream, upstream files that
  are new since the base toolchain, and files that are neither vendored nor excluded.
- Upstream test files are never vendored. The fork carries its own tests
  (`patch_test.go`, `patch_fingerprint_test.go`, `patch_e2e_test.go`).
- Server-only files (`server.go`, `write.go`, `writesched*.go`, `ciphers.go`, `gotrack.go`)
  stay out. The client subset compiles without them; only two symbols were shared and the
  fork supplies them in `patch.go` (`defaultMaxStreams`, `foreachHeaderElement`).
- The standard library package has no build-tag families, so there is nothing to copy
  verbatim by hash. If upstream introduces one, add it to `files.build_tag_family`; the
  checker picks the key up when it exists.

## Nested packages

- `net/http/internal/httpcommon` and `net/http/internal/httpsfv` are copied next to the
  package with their import paths rewritten. The copies are mandatory, not stylistic: the
  originals are only importable from inside `net/http/...`.
- `httpcommon` is a single file upstream. Keep it byte-identical except at
  `site-httpcommon-header-order` and `site-httpcommon-drop-server-api`.
- `httpsfv` is copied verbatim; `frame.go` imports it for RFC 9218 priority parsing.
- `scripts/httpcommon-diff.sh` asserts both properties for every copy rule.

## net/http/internal is not a copied package

- The vendored files reference four sentinels and one sniffer from the bare
  `net/http/internal` package. The standard library avoids importing `net/http` only to
  break an import cycle; the fork is a separate module, so `http.ErrAbortHandler`,
  `http.ErrBodyNotAllowed` and `http.ErrSkipAltProtocol` replace three of them,
  `DetectContentType` was only used by the dropped server file, and `ErrRequestCanceled` is
  internal to the client and becomes a local `errors.New`.
- `api.go` also declares `NoBody` and `LocalAddrContextKey`, which `net/http` assigns into
  the standard library copy at init time. The fork's own `init` does the same.
- Re-run the compiler after a re-base: if upstream starts using a new
  `net/http/internal` symbol, it shows up as an undefined identifier in the copied package.

## Deletions kept for the subset

`configFromServer` (server-only), the `ServerConfig`/`Handler`/`ResponseWriter`/`PushOptions`/
`ServerRequest`/`ConnState` surface in `api.go`, and the `NewServerRequest` family in
`httpcommon.go` are deleted so the client-only subset compiles. If upstream refactors them
into files the subset already vendors, the sites move; if upstream removes them outright,
the sites disappear and the manifest entries should be deleted in the same run.
