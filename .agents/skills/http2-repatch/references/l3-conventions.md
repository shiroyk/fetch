# L3 — conventions

These rules keep the vendored copy comparable with the toolchain's sources. They are what
make the next re-base cheap, so they apply even when a quicker edit is tempting.

## Edits are marked, never commented out

An edit to an upstream-owned file keeps the function where it is and marks the change:

```go
func (t *Transport) newClientConn(c net.Conn, singleUse bool, internalStateHook func()) (*ClientConn, error) {
	...
	// fork: site-new-client-conn. Options drive SETTINGS, the connection
	// WINDOW_UPDATE and the PRIORITY frames instead of the TransportConfig values.
	var settings []Setting
```

The marker names the manifest site, so `minimal-diff-check.sh` can prove that every
deviation from the toolchain's source is accounted for, and a reader can find the rule.

Deleting a whole upstream declaration is allowed when the fork replaces it in `patch.go`
(which is fork-owned and needs no marker), but a commented-out body never is:

- Commented code is not compiled, not vetted, and silently rots while upstream moves.
- It inflates the diff and makes "is this change intentional?" harder to answer.
- The authoritative copy of any upstream function is `$(go env GOROOT)/src/net/http/...`,
  not a comment in the fork.

If a tool that deletes upstream declarations walks upwards to swallow the doc comment
above them, keep the marker on its own line *after* the declaration you keep, or leave a
blank line so the marker is not treated as that declaration's doc comment.

## Where new code goes

Code with no upstream counterpart lives in `patch.go`: `Options`, the `TransportConfig`
adapter, the `*http.Request` adapter, `ConfigureTransport(s)`, `hackTlsConn`, and the helper
symbols the server files used to provide. Keeping it in one fork-owned file keeps "what did
we add?" and "what did we change?" separate questions.

## Upstream fidelity

- A vendored file with no manifest site targeting it must be byte-identical to the
  toolchain's copy. `scripts/minimal-diff-check.sh` enforces this.
- Copied files keep upstream's copyright header and comment style.
- Cosmetic deviations are defects. If a difference is not required by a site, remove it
  instead of recording it.

## Mutation rules

- Preferred order of edits: re-copy the whole file from the toolchain, then re-apply sites,
  rather than patching the previous fork in place. Re-copying is what makes upstream's
  refactors visible.
- Changes land as separate commits when they are independently useful: the re-copy plus
  sites, tests, then the skill or manifest updates.
- Never leave the tree in a state where a site is half-applied. A re-base either completes
  with every site verdicted, or it stops and reports.

## Tests

- Offline fingerprint tests live in `http2/patch_fingerprint_test.go` and must run without
  network access. `patch_e2e_test.go` drives a request through `net/http` over an
  in-memory pipe. Together they are the T2 gate.
- The live end-to-end fingerprint test stays in `http2/patch_test.go` behind `EXTNET`.
- When the profile changes, all three change together: they pin the same settings, window
  increment and header order.
- New tests must fail when the corresponding site is reverted; verify that before trusting
  them as a gate.

## Reporting

- One verdict per manifest site: `INTACT`, `SHIFTED`, or `BROKEN`.
- `SHIFTED` entries must name what moved and must be paired with an updated anchor in the
  manifest.
- `BROKEN` entries stop the re-base; report the failing precondition, the evidence, and the
  options, then wait for a decision.
- Record the target toolchain, `min_go` changes, and any new or retired site in the same
  report.
