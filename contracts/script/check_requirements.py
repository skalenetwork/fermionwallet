#!/usr/bin/env python3
"""Cross-reference this repository's English specifications with its checks.

Four specification documents carry stable requirement IDs:

    quantum-key-registry.md   [QKR-###]
    fermionguard-module.md    [GRD-###]
    pre-approval-engine.md    [ENG-###]
    fermionwallet.md          [FWL-###]   (the second product, FermionWallet)

Each document tags its normative sentences inline and ends with a "Requirement
index" table, one row per ID:

    | GRD-001 | Every security primitive is inherited from a pinned library. |

The TABLE ROW is the definition site. An inline `[GRD-001]` in the prose is a
use, not a definition -- otherwise every ID would be defined two or more times
and duplicate detection would be meaningless.

Tests, fuzz properties and symbolic proofs under contracts/test/ claim to
discharge a requirement with a `Covers:` annotation:

    /// Covers: [GRD-012], [QKR-009a]

The annotation attaches to whatever test function follows it, or -- when it sits
in a file-level doc comment -- to the file as a whole.

Exit status:

    1  a test references an ID no document defines, or a document defines the
       same ID twice.
    0  everything resolves; the coverage summary and the uncovered requirements
       are printed for the record. Incomplete coverage is a fact to report, not
       a build failure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# ── Layout ──────────────────────────────────────────────────────────────────

REPO = Path(__file__).resolve().parents[2]
TEST_ROOT = REPO / "contracts" / "test"

DOCS = {
    "GRD": REPO / "fermionguard-module.md",
    "ENG": REPO / "pre-approval-engine.md",
    "QKR": REPO / "quantum-key-registry.md",
    "FWL": REPO / "fermionwallet.md",
}

# `[a-z]?` suffix: [QKR-009a] is a real ID (a security fix refining [QKR-009]).
ID = r"(?:GRD|ENG|QKR|FWL)-[0-9]{3}[a-z]?"
ID_RE = re.compile(rf"\[({ID})\]")
# A definition: one row of a "Requirement index" table.
ROW_RE = re.compile(rf"^\|\s*({ID})\s*\|\s*(.*?)\s*\|\s*$")
COVERS_RE = re.compile(r"Covers:\s*(.+)$")
# `function test_x(`, `function testFuzz_x(`, `function invariant_x(`, `check_x(`
FUNC_RE = re.compile(r"^\s*function\s+((?:test|testFuzz|invariant_|check_)[A-Za-z0-9_]*)\s*\(")

# .md so a proof folder's README can cite what its lemmas discharge.
SOURCE_SUFFIXES = {".sol", ".py", ".md"}


# ── Parsing ─────────────────────────────────────────────────────────────────


def parse_docs() -> tuple[dict[str, str], list[str], list[str]]:
    """Return (id -> restatement, duplicate definitions, tagged-but-unindexed)."""
    defined: dict[str, str] = {}
    duplicates: list[str] = []
    unindexed: list[str] = []

    for prefix, path in DOCS.items():
        if not path.exists():
            sys.exit(f"missing specification document: {path}")
        text = path.read_text(encoding="utf-8")

        seen: dict[str, int] = {}
        for lineno, line in enumerate(text.splitlines(), 1):
            row = ROW_RE.match(line)
            if not row:
                continue
            rid, restatement = row.group(1), row.group(2)
            if rid in seen:
                duplicates.append(
                    f"{path.name}:{lineno}: [{rid}] defined again "
                    f"(first at line {seen[rid]})"
                )
                continue
            seen[rid] = lineno
            defined[rid] = restatement

        # An inline tag with no index row means the table drifted from the prose.
        inline = {m for m in ID_RE.findall(text) if m.startswith(prefix)}
        for rid in sorted(inline - set(seen)):
            unindexed.append(f"{path.name}: [{rid}] is tagged in the prose but has no index row")

    return defined, duplicates, unindexed


def parse_tests() -> dict[str, list[str]]:
    """Return id -> sorted list of "relative/path.sol::functionName" citations."""
    refs: dict[str, set[str]] = {}
    if not TEST_ROOT.exists():
        sys.exit(f"missing test tree: {TEST_ROOT}")

    for path in sorted(TEST_ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        rel = path.relative_to(REPO).as_posix()
        pending: list[str] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            covers = COVERS_RE.search(line)
            if covers:
                pending.extend(ID_RE.findall(covers.group(1)))
                continue
            func = FUNC_RE.match(line)
            if func and pending:
                for rid in pending:
                    refs.setdefault(rid, set()).add(f"{rel}::{func.group(1)}")
                pending = []
        # A `Covers:` with no following test function annotates the whole file.
        for rid in pending:
            refs.setdefault(rid, set()).add(rel)

    return {rid: sorted(where) for rid, where in refs.items()}


# ── Reporting ───────────────────────────────────────────────────────────────


def main() -> int:
    defined, duplicates, unindexed = parse_docs()
    refs = parse_tests()

    errors = list(duplicates)
    for rid in sorted(refs):
        if rid not in defined:
            for where in refs[rid]:
                errors.append(f"{where}: Covers [{rid}], which no document defines")

    if errors:
        print("FAIL: requirement traceability is broken\n")
        for e in errors:
            print(f"  {e}")
        return 1

    print("FermionGuard / FermionWallet requirement traceability")
    print("=" * 72)

    total_defined = 0
    total_covered = 0
    for prefix, path in DOCS.items():
        ids = sorted(r for r in defined if r.startswith(prefix))
        covered = [r for r in ids if r in refs]
        total_defined += len(ids)
        total_covered += len(covered)
        pct = 100.0 * len(covered) / len(ids) if ids else 0.0
        print(
            f"  {path.name:<28} {prefix}  {len(covered):>3}/{len(ids):<3} "
            f"requirements checked ({pct:5.1f}%)"
        )

    pct = 100.0 * total_covered / total_defined if total_defined else 0.0
    print("-" * 72)
    print(f"  {'total':<28}      {total_covered:>3}/{total_defined:<3} ({pct:5.1f}%)")
    citations = sum(len(w) for w in refs.values())
    print(f"  {citations} Covers citations across {len(refs)} requirements")

    for prefix, path in DOCS.items():
        uncovered = sorted(
            r for r in defined if r.startswith(prefix) and r not in refs
        )
        if not uncovered:
            continue
        print(f"\nNo check discharges these yet ({path.name}):")
        for rid in uncovered:
            print(f"  [{rid}] {defined[rid]}")

    if unindexed:
        print("\nWarnings:")
        for w in unindexed:
            print(f"  {w}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
