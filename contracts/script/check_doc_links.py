#!/usr/bin/env python3
"""Every link and file reference in the documentation points at something that exists.

Three times in one day this repository documented a file that did not exist: a
requirement-coverage script named by three specifications before anyone wrote it, a
proof folder's README cited by two Solidity files and a generated document, and a
model checker cited by the specification it was supposed to check. Each was found by a
person reading carefully. None had to be.

What is checked, for every tracked `*.md` outside `contracts/lib/` and `node_modules/`:

  - relative Markdown links `[text](path)` resolve to a file or directory;
  - their `#anchors`, when the target is Markdown, match a heading in it (GitHub's
    slug rules) or an explicit `id="..."`;
  - backticked paths that look like repository files — `contracts/src/Thing.sol`,
    `demo/server.py`, `scripts/foo.sh` — exist. This is the check that would have
    caught all three misses above, because none of them were Markdown links.

What is deliberately NOT checked: external URLs (no network in CI, and a link checker
that fails on someone else's outage is a link checker people disable), `mailto:`, and
bare words that merely contain a dot.

    python3 contracts/script/check_doc_links.py          # from the repository root
    python3 contracts/script/check_doc_links.py --list   # also print what it resolved
"""
import os
import re
import subprocess
import sys

# `[text](target)`, not preceded by `!` (images are checked the same way, so allow both).
LINK = re.compile(r"(?<!\\)\[(?P<text>[^\]]*)\]\((?P<target>[^)\s]+)(?:\s+\"[^\"]*\")?\)")
# A backticked token that looks like a path into this repository: at least one slash,
# a known source extension, and no spaces or globbing characters.
PATHISH = re.compile(
    r"`(?P<path>(?:[\w.\-]+/)+[\w.\-]+\.(?:sol|py|js|ts|rs|md|json|toml|yml|yaml|sh|html|svg|gif))`"
)
# Headings, including the `{#custom-id}` form, and explicit HTML anchors.
HEADING = re.compile(r"^#{1,6}\s+(?P<title>.+?)\s*(?:\{#(?P<explicit>[\w-]+)\})?\s*$", re.M)
HTML_ID = re.compile(r"\bid=[\"'](?P<id>[\w-]+)[\"']")

SKIP_PREFIXES = ("http://", "https://", "mailto:", "tel:", "#!", "data:")
# EIP drafts link sibling proposals as `./eip-N.md`, which resolve only once the file
# sits in the EIPs repository. `eips/check_eips.py` owns their shape; here they are
# simply not our files to find.
PROPOSAL_LINK = re.compile(r"^\./(?:eip|erc)-(?:[0-9]+|N)\.md$")
# Paths a document may name that are created at run time, not committed.
RUNTIME_PATHS = {
    "contracts/demo-state/deployment.json",
    "contracts/demo-state/ledger-device.json",
    "demo-state/deployment.json",
    "demo-state/ledger-device.json",
}
# Paths in OTHER people's repositories, which prose cites by their own names. Each is a
# citation, not a file we own; keeping the list short and explicit is the point, because
# an allowlist that grows is one nobody reads.
EXTERNAL_PATHS = {
    "doc/apdu.md", "doc/APDU.md",        # LedgerHQ/app-ethereum, LedgerHQ/app-boilerplate
    "config/eipw.toml",                  # ethereum/ERCs
    "src/xmss/xmss.sol", "contracts/WOTSPlus.sol",  # the poqeth survey in the module spec
}
# Import paths that a Solidity remapping resolves, not filesystem paths.
REMAPPED_PREFIXES = ("xmss-solidity/", "@openzeppelin/", "@safe-global/", "forge-std/")


def slug(title):
    """GitHub's heading-to-anchor rule: strip formatting, lowercase, spaces to hyphens."""
    t = re.sub(r"`([^`]*)`", r"\1", title)            # code spans
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)     # links keep their text
    t = re.sub(r"[*_~]", "", t)                        # emphasis
    t = t.strip().lower()
    t = re.sub(r"[^\w\s-]", "", t)                     # punctuation goes
    # One hyphen per space, NOT per run: GitHub turns "A & B" into "a--b", because the
    # ampersand is deleted and the two spaces around it each become a hyphen. Collapsing
    # runs here silently invents anchors that do not exist, which is the opposite of the
    # job.
    return re.sub(r"\s", "-", t)


def anchors_of(path):
    text = open(path, encoding="utf-8").read()
    found = set()
    for m in HEADING.finditer(text):
        found.add(m.group("explicit") or slug(m.group("title")))
    found.update(m.group("id") for m in HTML_ID.finditer(text))
    return found


def tracked_markdown(root):
    out = subprocess.run(["git", "-C", root, "ls-files", "*.md"],
                         capture_output=True, text=True, check=True)
    for rel in out.stdout.split():
        if rel.startswith("contracts/lib/") or "node_modules/" in rel:
            continue
        yield rel


def all_tracked(root):
    """Every tracked path, including submodule contents, which git lists separately."""
    out = subprocess.run(["git", "-C", root, "ls-files", "--recurse-submodules"],
                         capture_output=True, text=True)
    if out.returncode != 0:  # older git, or a submodule not checked out
        out = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, check=True)
    return set(out.stdout.split())


def check(root, verbose=False):
    problems, resolved = [], 0
    anchor_cache = {}
    tracked = all_tracked(root)

    for rel in tracked_markdown(root):
        path = os.path.join(root, rel)
        base = os.path.dirname(path)
        text = open(path, encoding="utf-8").read()

        for m in LINK.finditer(text):
            target = m.group("target")
            if target.startswith(SKIP_PREFIXES):
                continue
            line = text[: m.start()].count("\n") + 1
            file_part, _, anchor = target.partition("#")

            if PROPOSAL_LINK.match(target):
                continue
            if not file_part:                     # same-document anchor
                dest = path
            else:
                dest = os.path.normpath(os.path.join(base, file_part))
                if not os.path.exists(dest):
                    if os.path.relpath(dest, root) in RUNTIME_PATHS:
                        continue
                    problems.append(f"{rel}:{line}: link to {file_part!r} — no such file")
                    continue
                # Exists here and nowhere else: the link is broken for everyone but the
                # person who wrote it, and CI is the first to find out.
                here = os.path.relpath(dest, root)
                if here not in tracked and os.path.isfile(dest) and here not in RUNTIME_PATHS:
                    problems.append(
                        f"{rel}:{line}: link to {file_part!r} — the file exists in this working tree "
                        "but is not committed, so the link is broken for everyone else"
                    )
                    continue
            resolved += 1

            if anchor and dest.endswith(".md"):
                if dest not in anchor_cache:
                    anchor_cache[dest] = anchors_of(dest)
                if anchor not in anchor_cache[dest]:
                    where = "this document" if dest == path else os.path.relpath(dest, root)
                    problems.append(f"{rel}:{line}: #{anchor} is not a heading in {where}")
            if verbose:
                print(f"  {rel}:{line} -> {os.path.relpath(dest, root)}"
                      + (f"#{anchor}" if anchor else ""))

        for m in PATHISH.finditer(text):
            p = m.group("path")
            if p in RUNTIME_PATHS or p in EXTERNAL_PATHS or p.startswith(REMAPPED_PREFIXES):
                continue
            # "../fermionguard-module.md" and "./ledger-app/build.sh" both name real files.
            bare = re.sub(r"^(?:\.\.?/)+", "", p)
            line = text[: m.start()].count("\n") + 1
            # Prose names a file the way a reader would say it aloud: `contracts/README.md`
            # writes `src/FermionGuard.sol`, and `py/xmss_ref.py` for a file in the
            # submodule. So the question asked here is "does a file with this path suffix
            # exist at all", not "does this path resolve from this directory" — which is
            # what a reader wants to know, and what the three misses this script exists for
            # would each have failed.
            if bare in tracked or any(t.endswith("/" + bare) for t in tracked):
                resolved += 1
                continue
            problems.append(f"{rel}:{line}: `{p}` does not exist anywhere in the tree")

    return problems, resolved


def main():
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True, check=True).stdout.strip()
    problems, resolved = check(root, verbose="--list" in sys.argv)
    if problems:
        print(f"{len(problems)} broken reference(s):")
        for p in problems:
            print(f"  {p}")
        return 1
    print(f"documentation references: {resolved} resolved, none broken")
    return 0


if __name__ == "__main__":
    sys.exit(main())
