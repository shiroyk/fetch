#!/usr/bin/env python3
"""Re-base checks for the vendored net/http/internal/http2 copy.

Driven by references/patch-manifest.json. The .sh wrappers in this directory are
the public entry points; this module holds the logic so the manifest is parsed in
exactly one place.

Usage: check.py {subset|httpcommon|minimal-diff|verify} [go version]
"""

from __future__ import annotations

import fnmatch
import filecmp
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
REPO = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    or Path.cwd()
)
MANIFEST = json.loads((SKILL_DIR / "references" / "patch-manifest.json").read_text())
PACKAGE_DIR = REPO / MANIFEST["fork_dir"]


def go_env(name: str) -> str:
    return subprocess.run(
        ["go", "env", name], capture_output=True, text=True, check=True
    ).stdout.strip()


def version_arg(argv: list[str]) -> str:
    if len(argv) > 1:
        return argv[1]
    return MANIFEST["base_go"]


def upstream_root(version: str) -> Path:
    """The vendored source comes from the toolchain's GOROOT, not from a module cache."""
    root = Path(go_env("GOROOT")) / MANIFEST["upstream_root"]
    if not root.is_dir():
        sys.exit(
            f"{root} does not exist; the toolchain has no net/http/internal sources"
        )
    actual = go_env("GOVERSION")
    if version and version != actual:
        print(
            f"warning: manifest base is {version} but this toolchain is {actual};"
            f" comparing against {actual}"
        )
    return root


def upstream_package(version: str) -> Path:
    return upstream_root(version) / MANIFEST["upstream_package"]


def is_test(name: str) -> bool:
    return name.endswith("_test.go")


def excluded(name: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/"):
            if name == pattern.rstrip("/"):
                return True
        elif fnmatch.fnmatch(name, pattern):
            return True
    return False


def build_tag_names(version: str) -> list[str]:
    names: set[str] = set()
    for family in MANIFEST["files"].get("build_tag_family", []):
        for pattern in family["globs"]:
            names.update(
                p.name for p in upstream_package(version).glob(pattern) if p.is_file()
            )
    return sorted(names)


def report(title: str) -> None:
    print(f"\n== {title} ==")


def subset(version: str) -> int:
    src = upstream_package(version)
    failures: list[str] = []

    report(f"allowlist against {src}")
    for name in MANIFEST["files"]["allowlist"]:
        if (src / name).is_file():
            print(f"  ok        {name}")
        else:
            print(f"  MISSING   {name}")
            failures.append(f"allowlist entry {name} no longer exists upstream")

    families = build_tag_names(version)
    if families:
        report("build-tag families (must stay byte-identical)")
        for name in families:
            fork = PACKAGE_DIR / name
            if not fork.is_file():
                print(f"  MISSING   {name} (not vendored)")
                failures.append(f"build-tag file {name} is not vendored")
            elif filecmp.cmp(src / name, fork, shallow=False):
                print(f"  ok        {name}")
            else:
                print(f"  DRIFTED   {name}")
                failures.append(f"build-tag file {name} differs from upstream")

    report("upstream files not vendored")
    known = set(MANIFEST["files"]["allowlist"]) | set(families)
    patterns = MANIFEST["files"]["exclude"]
    nested_names = {rule["from"].rstrip("/").split("/")[-1] for rule in MANIFEST["files"]["nested"]["copy"]}
    for path in sorted(src.iterdir()):
        name = path.name
        if name in known or is_test(name):
            continue
        if name in nested_names:
            print(f"  nested    {name}/ (copied by a nested rule)")
            continue
        if path.is_dir():
            if excluded(name, patterns) or excluded(f"{name}/", patterns):
                print(f"  excluded  {name}/")
            else:
                print(f"  NEW       {name}/ (not in allowlist or exclude)")
                failures.append(f"unclassified upstream directory {name}/")
            continue
        if name == ".gitignore" or excluded(name, patterns):
            print(f"  excluded  {name}")
        else:
            print(f"  NEW       {name} (not in allowlist or exclude)")
            failures.append(f"unclassified upstream file {name}")

    report("fork files with no upstream counterpart")
    upstream_names = {p.name for p in src.iterdir()}
    for path in sorted(PACKAGE_DIR.glob("*.go")):
        if path.name in upstream_names:
            continue
        listed = path.name in MANIFEST["files"].get("fork_owned", [])
        print(f"  {'fork-owned' if listed else 'UNLISTED  '} {path.name}")
        if not listed:
            failures.append(f"{path.name} is fork-owned but missing from files.fork_owned")

    if failures:
        report("result")
        for failure in failures:
            print(f"  fail: {failure}")
        return 1
    print("\nsubset-check: ok")
    return 0


def httpcommon(version: str) -> int:
    failures: list[str] = []
    for rule in MANIFEST["files"]["nested"]["copy"]:
        src = upstream_root(version) / rule["from"]
        dst = REPO / rule["to"]
        fork_owned = set(rule.get("fork_owned", []))
        patched = set(rule.get("patched", []))

        report(f"{rule['to']} against {rule['from']}")
        if not src.is_dir():
            print(f"  MISSING   upstream {rule['from']} does not exist in this version")
            failures.append(f"upstream {rule['from']} is gone; re-derive the copy rule")
            continue
        for path in sorted(src.glob("*.go")):
            if is_test(path.name):
                continue
            fork = dst / path.name
            if not fork.is_file():
                print(f"  MISSING   {path.name}")
                failures.append(f"{path.name} is not copied into the fork")
            elif filecmp.cmp(path, fork, shallow=False):
                print(f"  identical {path.name}")
            elif path.name in patched:
                print(f"  patched   {path.name} (expected site)")
            else:
                print(f"  DEVIATES  {path.name}")
                failures.append(f"{path.name} differs from upstream but is not a listed site")

        for name in sorted(fork_owned):
            if (dst / name).is_file():
                print(f"  fork      {name}")
            else:
                print(f"  MISSING   {name} (fork-owned)")
                failures.append(f"fork-owned {name} is missing")

        for name in sorted(patched):
            if (dst / name).is_file() and filecmp.cmp(src / name, dst / name, shallow=False):
                failures.append(f"{name} is identical to upstream; the site that patches it was lost")

    if failures:
        report("result")
        for failure in failures:
            print(f"  fail: {failure}")
        return 1
    print("\nhttpcommon-diff: ok")
    return 0


MODIFYING_KINDS = {
    "build-constraint",
    "new-file",
    "replace-symbol",
    "signature-relax",
    "import-rewrite",
    "call-site-inline",
    "delete-symbol",
}


def expected_diffs() -> set[str]:
    upstream_owned = set(MANIFEST["files"]["allowlist"])
    expected: set[str] = set()
    for site in MANIFEST["sites"]:
        if site["kind"] not in MODIFYING_KINDS:
            continue
        for target in site["targets"]:
            match = re.fullmatch(r"http2/([A-Za-z0-9_]+\.go)", target["file"])
            if match and match.group(1) in upstream_owned:
                expected.add(match.group(1))
    return expected


def minimal_diff(version: str) -> int:
    src = upstream_package(version)
    expected = expected_diffs()
    actual: set[str] = set()
    failures: list[str] = []

    report("vendored files that differ from upstream")
    names = sorted(set(MANIFEST["files"]["allowlist"]) | set(build_tag_names(version)))
    for name in names:
        fork = PACKAGE_DIR / name
        if not fork.is_file():
            continue
        if not filecmp.cmp(src / name, fork, shallow=False):
            actual.add(name)
            marker = "site" if name in expected else "UNEXPECTED"
            print(f"  {marker:10} {name}")
            if name not in expected:
                failures.append(f"{name} differs from upstream but no site targets it")

    for name in sorted(expected - actual):
        print(f"  MISSING    {name} (a site expects this file to differ)")
        failures.append(f"{name} is identical to upstream; the site that changes it was lost")

    report("conventions")
    commented = subprocess.run(
        ["grep", "-rn", "-E", r"^//func ", str(PACKAGE_DIR)],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if commented:
        print("  commented-out upstream functions found:")
        print(commented)
        failures.append("commented-out function bodies are not allowed (see L3)")
    else:
        print("  no commented-out function bodies")

    # Every site that touches an upstream-owned file must leave a marker naming it, so a
    # reader of the vendored file can tell an intentional edit from drift.
    sources = "\n".join(
        path.read_text() for path in PACKAGE_DIR.rglob("*.go")
    )
    nested_owned = set()
    for rule in MANIFEST["files"]["nested"]["copy"]:
        to = rule["to"]
        nested_owned.add(to.rstrip("/"))
    upstream_owned = {f"http2/{name}" for name in MANIFEST["files"]["allowlist"]}
    for site in MANIFEST["sites"]:
        if site.get("meta"):
            # Sites that only describe a convention have no edit of their own.
            continue
        touches_upstream = False
        for target in site["targets"]:
            path = target["file"].rstrip("/")
            if path in upstream_owned or path in nested_owned or any(
                path.startswith(owned + "/") for owned in nested_owned
            ):
                touches_upstream = True
        if not touches_upstream:
            continue
        if site["id"] in sources:
            print(f"  marker    {site['id']}")
        else:
            print(f"  NO MARKER {site['id']}")
            failures.append(
                f"no // fork: marker in http2/ names {site['id']}; an upstream edit is unmarked"
            )

    if failures:
        report("result")
        for failure in failures:
            print(f"  fail: {failure}")
        return 1
    print("\nminimal-diff-check: ok")
    return 0


def writable_gocache() -> str | None:
    for candidate in (os.environ.get("GOCACHE"), None):
        path = Path(candidate) if candidate else Path(go_env("GOCACHE"))
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write-probe"
            probe.write_text("")
            probe.unlink()
            return str(path)
        except OSError:
            continue
    fallback = tempfile.mkdtemp(prefix="http2repatch-gocache-")
    print(f"note: default GOCACHE is not writable, using {fallback}")
    return fallback


def run(label: str, argv: list[str], cache: str | None, drop_env: tuple[str, ...] = ()) -> bool:
    env = dict(os.environ)
    if cache:
        env["GOCACHE"] = cache
    for name in drop_env:
        env.pop(name, None)
    proc = subprocess.run(argv, cwd=REPO, env=env)
    ok = proc.returncode == 0
    print(f"  {label}: {'ok' if ok else 'FAILED'}")
    return ok


def verify(version: str) -> int:
    cache = writable_gocache()
    report("T1 compile and vet")
    ok = run("go build ./...", ["go", "build", "./..."], cache)
    ok = run("go vet ./http2/...", ["go", "vet", "./http2/..."], cache) and ok

    report("T2 offline fingerprint")
    # EXTNET would turn TestFingerPrint into a live network call; the gate must stay offline.
    ok = run(
        "go test ./http2/ -count=1",
        ["go", "test", "./http2/", "-count=1"],
        cache,
        drop_env=("EXTNET",),
    ) and ok

    report("T4 patch minimality")
    ok = minimal_diff(version) == 0 and ok

    report("result")
    print("verify: ok" if ok else "verify: FAILED")
    return 0 if ok else 1


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in {"subset", "httpcommon", "minimal-diff", "verify"}:
        print(__doc__)
        return 2
    command = sys.argv[1]
    version = version_arg(sys.argv[1:])
    if command == "subset":
        return subset(version)
    if command == "httpcommon":
        return httpcommon(version)
    if command == "minimal-diff":
        return minimal_diff(version)
    return verify(version)


if __name__ == "__main__":
    sys.exit(main())
