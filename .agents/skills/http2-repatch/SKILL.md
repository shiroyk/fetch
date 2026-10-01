---
name: http2-repatch
description: Re-apply this repository's uTLS patch to the vendored golang.org/x/net/http2 copy after re-basing onto a different x/net version. Use when bumping golang.org/x/net, refreshing or re-copying http2/ from upstream, or when HTTP/2 fingerprint behaviour in github.com/shiroyk/fetch/http2 must keep working after an upstream change.
---

# HTTP/2 Repatch

`http2/` is not an upstream package: it is a subset of the standard library's
`net/http/internal/http2` that has
been patched so the client speaks HTTP/2 through `github.com/refraction-networking/utls`
and emits a caller-controlled HTTP/2 fingerprint. The patch is expressed as rules, not as
a stored diff, so it has to be re-derived whenever upstream moves.

The rules live in `references/patch-manifest.json`. It records the base version, the file
selection, and one entry per patch site. Read it before touching anything.

## Workflow

1. **Pin the target toolchain.** The vendored copy comes from the Go toolchain's own
   sources at `$(go env GOROOT)/src/net/http/internal/http2`; as of Go 1.27 that package is
   the source of truth, and `golang.org/x/net/http2` only receives critical fixes. Record
   the toolchain in `base_go`, copy from the toolchain named there, and move `min_go` with
   it. `hpack`, `httpguts` and `idna` still come from `golang.org/x/net`, so re-check that
   dependency separately. With no toolchain given, read `base_go` and run the same checks
   as a regression self-check.
2. **Select files.** Run `scripts/subset-check.sh <version>`: it reports allowlist entries
   that vanished, upstream files that are new since the base version, and build-tag family
   files whose bytes drifted.
3. **Re-apply each site.** Walk `sites` in the manifest. For every site, decide a verdict
   before editing:
   - `INTACT` — anchors found, invariants still hold: re-apply mechanically.
   - `SHIFTED` — anchors moved, were renamed, changed signature, or split across files,
     but the intent is still identifiable: adapt, then update the site's anchors in the
     manifest so the next run re-aligns.
   - `BROKEN` — a precondition no longer holds: stop, report, and hand the decision back
     to the user. Do not guess and do not improvise a different mechanism.
4. **Verify.** Run `scripts/verify.sh <version>` and read the layered references only when
   a site's verdict is not `INTACT`.
5. **Report.** Give one verdict per site, in manifest order, including the sites that
   needed no change. Update `base_version` in the manifest when the re-base lands.

No site may be silently skipped or silently dropped: the report must contain exactly one
verdict for every entry in `sites`.

## Layer references

- `references/patch-analysis.md` — what the patch does and why each site exists.
- `references/l1-behavior.md` — uTLS injection, `Options` plumbing, fingerprint ordering.
- `references/l2-structure.md` — file subset, build-tag families, `internal/httpcommon`.
- `references/l3-conventions.md` — replaced functions, pointer comments, mutation rules.
- `references/patch-manifest.json` — the machine-readable site list and file allowlist.

## Verification layers

| Layer | Command | Required |
| --- | --- | --- |
| T1 compile + vet | `go build ./... && go vet ./http2/...` | always |
| T2 offline fingerprint | `go test ./http2/ -count=1` (offline; `TestFingerPrint` skips itself) | always |
| T3 live fingerprint | `EXTNET=1 go test ./http2/ -run TestFingerPrint` | release-time, needs network |
| T4 patch minimality | `scripts/minimal-diff-check.sh <version>` | always |

`scripts/verify.sh` runs T1, T2 and T4. T2 is the only fully offline proof of the
fingerprint, so a re-base is not complete while it fails.

## Constraints

- Never edit files that upstream owns and the fork does not patch. If a file outside the
  allowlist needs a change, the site list is wrong — fix the list, not the file.
- Never reintroduce commented-out upstream implementations. Replaced functions are deleted
  in place and marked with a pointer comment naming the manifest site.
- Keep `internal/httpcommon` byte-identical to upstream except for its enumerated sites.
- uTLS behaviour has no fallback: if the uTLS path cannot be re-applied, the patch is
  broken rather than degraded.
- The standard library package is designed to be driven by `net/http`, so it speaks its own
  `ClientRequest`/`ClientResponse` types and takes a `TransportConfig` rather than a
  `*http.Transport`. The fork supplies that adapter layer itself; net/http's own adapter is
  unexported and cannot be imported.
- `net/http` never uses a vendored copy of its own HTTP/2 engine. The fork therefore
  installs itself on the caller's `http.Transport` through `TLSNextProto`, and every
  upstream-owned edit carries a `// fork: <site-id>` marker.
