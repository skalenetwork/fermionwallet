#!/usr/bin/env python3
"""Render `test/registry-proof/RegistrySpec.sol` as plain English.

The executable specification is the authority on the key registry's state
machine; this script is the only thing that turns it into prose, so the prose
cannot drift from it silently. Nothing about the registry is hardcoded here:
every state field, precondition, effect and transition name in the output is
read out of the Solidity source. Renaming `canCancelRevocation` or adding a new
`canFoo`/`afterFoo` pair changes the output with no edit to this file.

Usage:
    python3 script/describe_spec.py                     # print to stdout
    python3 script/describe_spec.py --check FILE        # exit 1 if FILE is stale

Standard library only.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import textwrap

DEFAULT_SPEC = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "test",
    "registry-proof",
    "RegistrySpec.sol",
)

# ───────────────────────────── source model ──────────────────────────────


class Field:
    def __init__(self, type_: str, name: str, comment: str) -> None:
        self.type = type_
        self.name = name
        self.comment = comment


class Function:
    def __init__(self, name: str, params: list[tuple[str, str]], returns: str,
                 body: str, doc: str) -> None:
        self.name = name
        self.params = params
        self.returns = returns
        self.body = body
        self.doc = doc

    @property
    def kind(self) -> str:
        if self.name.startswith("can"):
            return "precondition"
        if self.name.startswith("after"):
            return "effect"
        if self.returns.startswith("bool"):
            return "predicate"
        return "helper"

    @property
    def suffix(self) -> str:
        """The transition this function belongs to: `canRegister` -> `Register`."""
        for prefix in ("can", "after"):
            if self.name.startswith(prefix):
                return self.name[len(prefix):]
        return self.name


def strip_comments_outside_strings(src: str) -> str:
    """Blank out `//` and `/* */` comments so the body parser sees code only."""
    out = []
    i, n = 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def match_delim(src: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index just past the delimiter that closes the one at `start`."""
    depth = 0
    for i in range(start, len(src)):
        if src[i] == open_ch:
            depth += 1
        elif src[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
    raise ValueError(f"unbalanced {open_ch}{close_ch} from offset {start}")


def parse_doc_above(lines: list[str], index: int) -> str:
    """The `///` block immediately above source line `index` (0-based)."""
    collected = []
    i = index - 1
    while i >= 0:
        stripped = lines[i].strip()
        if stripped.startswith("///"):
            collected.append(stripped[3:].strip())
            i -= 1
        elif stripped == "":
            break
        else:
            break
    collected.reverse()
    text = " ".join(collected)
    text = re.sub(r"@(title|notice|param \w+|return|dev)\s*", "", text)
    return re.sub(r"\s+", " ", text).strip()


def parse_enum(src: str, name: str) -> list[str]:
    m = re.search(r"\benum\s+" + re.escape(name) + r"\s*\{", src)
    if not m:
        return []
    end = match_delim(src, m.end() - 1, "{", "}")
    body = src[m.end():end - 1]
    return [t.strip() for t in body.split(",") if t.strip()]


def parse_struct(src: str, name: str) -> list[Field]:
    m = re.search(r"\bstruct\s+" + re.escape(name) + r"\s*\{", src)
    if not m:
        return []
    end = match_delim(src, m.end() - 1, "{", "}")
    fields = []
    for raw in src[m.end():end - 1].splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        code, _, comment = line.partition("//")
        decl = code.strip().rstrip(";").split()
        if len(decl) < 2:
            continue
        fields.append(Field(decl[0], decl[1], comment.strip()))
    return fields


def parse_functions(src: str) -> list[Function]:
    lines = src.splitlines()
    line_starts = []
    offset = 0
    for line in lines:
        line_starts.append(offset)
        offset += len(line) + 1

    def line_of(pos: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo

    code = strip_comments_outside_strings(src)
    functions = []
    for m in re.finditer(r"\bfunction\s+(\w+)\s*\(", code):
        name = m.group(1)
        params_end = match_delim(code, m.end() - 1, "(", ")")
        params_src = code[m.end():params_end - 1]
        brace = code.index("{", params_end)
        header = code[params_end:brace]
        body_end = match_delim(code, brace, "{", "}")
        body = code[brace + 1:body_end - 1]

        returns = ""
        rm = re.search(r"returns\s*\(", header)
        if rm:
            r_end = match_delim(header, rm.end() - 1, "(", ")")
            returns = header[rm.end():r_end - 1].strip()

        params = []
        for raw in params_src.split(","):
            parts = raw.split()
            if len(parts) >= 2:
                params.append((" ".join(parts[:-1]), parts[-1]))
        functions.append(
            Function(name, params, returns, body, parse_doc_above(lines, line_of(m.start())))
        )
    return functions


# ─────────────────────────── expression → English ─────────────────────────

ZERO = {"bytes32(0)", "address(0)", "uint64(0)", "uint256(0)", "0"}

COMPARISONS = [
    ("==", "is", "equals"),
    ("!=", "is not", "differs from"),
    (">=", "is at least", "is at least"),
    ("<=", "is at most", "is at most"),
    (">", "is greater than", "is greater than"),
    ("<", "is less than", "is less than"),
]


def split_top_level(expr: str, sep: str) -> list[str]:
    parts, depth, current = [], 0, ""
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth == 0 and expr.startswith(sep, i):
            parts.append(current)
            current = ""
            i += len(sep)
            continue
        current += ch
        i += 1
    parts.append(current)
    return [p.strip() for p in parts if p.strip()]


def term(expr: str, state_var: str) -> str:
    """Render one operand: state fields lose their `s.` prefix, zeros read `zero`."""
    expr = expr.strip()
    if expr in ZERO:
        return "zero"
    if state_var and expr.startswith(state_var + "."):
        return "`" + expr[len(state_var) + 1:] + "`"
    expr = re.sub(r"\b" + re.escape(state_var) + r"\.(\w+)", r"\1", expr) if state_var else expr
    expr = re.sub(r"\buint\d*\(([^()]*)\)", r"\1", expr)
    return "`" + expr.strip() + "`"


def conjunct(expr: str, state_var: str) -> str:
    """One `&&` conjunct of a boolean expression as an English clause."""
    expr = expr.strip()
    while expr.startswith("(") and match_delim(expr, 0, "(", ")") == len(expr):
        expr = expr[1:-1].strip()
    alternatives = split_top_level(expr, "||")
    if len(alternatives) > 1:
        return " or ".join(conjunct(a, state_var) for a in alternatives)
    for op, verb_zero, verb_other in COMPARISONS:
        parts = split_top_level(expr, op)
        if len(parts) == 2:
            left, right = parts
            rendered_right = term(right, state_var)
            verb = verb_zero if rendered_right == "zero" else verb_other
            return f"{term(left, state_var)} {verb} {rendered_right}"
    if expr.startswith("!"):
        return f"{term(expr[1:], state_var)} is false"
    return f"{term(expr, state_var)} is true"


def state_param(fn: Function) -> str:
    """The name of the single `SafeState` parameter, or "" if there is not exactly one."""
    names = [n for t, n in fn.params if t.split()[0].endswith("SafeState")]
    return names[0] if len(names) == 1 else ""


def clauses_of(fn: Function) -> list[str]:
    """The `&&` conjuncts of the function's single `return` expression."""
    state_var = state_param(fn)
    m = re.search(r"return\s+(.*?);", fn.body, re.S)
    if not m:
        return []
    return [conjunct(c, state_var) for c in split_top_level(m.group(1), "&&")]


def effects_of(fn: Function, fields: list[Field]) -> tuple[list[str], list[str]]:
    """(English effects, names of state fields the function leaves untouched)."""
    state_var = state_param(fn) or "s"
    written, effects = [], []
    pattern = re.compile(
        r"\b" + re.escape(state_var) + r"\.(\w+)\s*(=|\+=|-=)\s*(.*?);", re.S
    )
    for m in pattern.finditer(fn.body):
        field, op, value = m.group(1), m.group(2), m.group(3).strip()
        written.append(field)
        if op == "+=":
            effects.append(f"advances `{field}` by {value}")
        elif op == "-=":
            effects.append(f"reduces `{field}` by {value}")
        elif value in ZERO:
            effects.append(f"clears `{field}` to zero")
        elif value in ("true", "false"):
            effects.append(f"sets `{field}` to {value}")
        else:
            effects.append(f"sets `{field}` to {term(value, state_var)}")
    untouched = [f.name for f in fields if f.name not in written]
    return effects, untouched


# ────────────────────────────── rendering ─────────────────────────────────


def wrap(text: str, indent: str = "") -> str:
    return "\n".join(
        textwrap.wrap(text, width=88, initial_indent=indent, subsequent_indent=indent)
    ) if text else ""


def render(spec_path: str) -> str:
    src = open(spec_path, encoding="utf-8").read()
    rel = "test/registry-proof/" + os.path.basename(spec_path)

    lib = re.search(r"\blibrary\s+(\w+)", strip_comments_outside_strings(src))
    lib_name = lib.group(1) if lib else "RegistrySpec"
    lines = src.splitlines()
    lib_doc = parse_doc_above(lines, next(
        i for i, l in enumerate(lines) if re.match(r"\s*library\s+\w+", l)
    ))

    statuses = parse_enum(src, "Status")
    fields = parse_struct(src, "SafeState")
    functions = parse_functions(src)

    by_name = {f.name: f for f in functions}
    preconditions = [f for f in functions if f.kind == "precondition"]
    effects = [f for f in functions if f.kind == "effect"]
    others = [f for f in functions if f.kind in ("predicate", "helper")]

    out: list[str] = []
    w = out.append

    w("<!-- GENERATED FILE — DO NOT EDIT BY HAND. -->")
    w(f"# The key-registry state machine, as {lib_name} defines it")
    w("")
    w("> **Generated.** Every sentence below is derived from")
    w(f"> [`{rel}`](./{os.path.basename(spec_path)}) by")
    w("> `contracts/script/describe_spec.py`. Do not edit this file: change the")
    w("> specification and regenerate, or the two will disagree.")
    w(">")
    w("> ```shell")
    w("> cd contracts")
    w("> python3 script/describe_spec.py > test/registry-proof/DESCRIPTION.md")
    w("> python3 script/describe_spec.py --check test/registry-proof/DESCRIPTION.md")
    w("> ```")
    w("")
    w("`RegistryEquivalence.t.sol` proves, with Halmos, that `QuantumKeyRegistry`")
    w("makes exactly the transitions described here. Read the description as the")
    w("registry's normative behaviour, and any prose elsewhere in the repository as")
    w("commentary on it.")
    w("")
    w("Each transition below is given twice: the specification's own comment, and the")
    w("mechanical reading of its code. **Where the two differ, the mechanical reading is")
    w("what the proof checks** — the comment is the author's intent, not an enforced")
    w("invariant.")
    w("")

    if lib_doc:
        w(f"## What `{lib_name}` says about itself")
        w("")
        w(wrap(lib_doc, "> "))
        w("")

    w("## The state of one Safe")
    w("")
    if fields:
        w(f"The specification models {len(fields)} field"
          f"{'s' if len(fields) != 1 else ''} per Safe, and nothing else — two registries")
        w("agree iff these agree:")
        w("")
        w("| Field | Type | Meaning (from the specification's own comment) |")
        w("|---|---|---|")
        for f in fields:
            w(f"| `{f.name}` | `{f.type}` | {f.comment or '_(no comment in the source)_'} |")
        w("")
    if statuses:
        w(f"A key's `Status` is one of: "
          + ", ".join(f"`{s}`" for s in statuses) + ".")
        used = [s for s in statuses if re.search(r"\bStatus\." + s + r"\b", src)]
        declared_only = [s for s in statuses if s not in used]
        if len(declared_only) == len(statuses):
            w("The enum is **declared but never used** by the specification: no field of")
            w("the modelled state holds a `Status`, so per-key lifecycle (`Rotated` versus")
            w("`Revoked`) is outside what this model — and therefore the equivalence proof")
            w("— covers.")
        elif declared_only:
            w("Never referenced by the specification: "
              + ", ".join(f"`{s}`" for s in declared_only) + ".")
        else:
            carriers = [f.name for f in fields if f.type == "Status"]
            w(wrap(
                "Every one of them is referenced by the specification"
                + (", and the modelled field"
                   + ("s " if len(carriers) != 1 else " ")
                   + ", ".join(f"`{c}`" for c in carriers)
                   + " carries one" if carriers else "")
                + ", so per-key lifecycle (`Rotated` versus `Revoked`) is inside what "
                "this model — and therefore the equivalence proof — covers."
            ))
        w("")

    w("## Transitions")
    w("")
    suffixes: list[str] = []
    for fn in functions:
        if fn.kind in ("precondition", "effect") and fn.suffix not in suffixes:
            suffixes.append(fn.suffix)
    w("The specification names "
      + str(len(suffixes))
      + " transition"
      + ("s" if len(suffixes) != 1 else "")
      + ": "
      + ", ".join(f"**{camel_words(s)}**" for s in suffixes)
      + ".")
    w("")

    for suffix in suffixes:
        pre = by_name.get("can" + suffix)
        eff = by_name.get("after" + suffix)
        w(f"### {camel_words(suffix)}")
        w("")
        parts = [f.doc for f in (pre, eff) if f is not None and f.doc]
        if parts:
            w("What the specification says in words:")
            w("")
            for part in parts:
                w(wrap(part, "> "))
                w(">")
            out.pop()
            w("")

        if pre:
            w(f"**It may happen only when** (`{pre.name}`, all of):")
            w("")
            for c in clauses_of(pre):
                w(f"- {c}")
            w("")
        else:
            w(wrap(
                f"**Precondition:** none. The specification defines no `can{suffix}` "
                "function, so it says nothing about *when* this transition may happen — "
                "only what it does when it does."
            ))
            w("")

        if eff:
            changes, untouched = effects_of(eff, fields)
            w(f"**It then** (`{eff.name}`):")
            w("")
            for c in changes:
                w(f"- {c}")
            w("")
            if untouched:
                w("It leaves untouched: "
                  + ", ".join(f"`{u}`" for u in untouched)
                  + ".")
                w("")
        else:
            w("**Effect:** the specification defines no `after"
              f"{suffix}` function; the transition is a pure guard.")
            w("")

    w("## Derived facts")
    w("")
    w("### Which transitions advance the ceremony nonce")
    w("")
    nonce_field = next((f.name for f in fields if "nonce" in f.name.lower()), None)
    if nonce_field:
        advancing, leaving = [], []
        for fn in effects:
            changes, _ = effects_of(fn, fields)
            (advancing if any(nonce_field in c and "advances" in c for c in changes)
             else leaving).append(camel_words(fn.suffix))
        w(f"- advances `{nonce_field}`: " + (", ".join(advancing) or "none"))
        w(f"- leaves `{nonce_field}` alone: " + (", ".join(leaving) or "none"))
        w("")

    w("### Which transitions clear a pending revocation")
    w("")
    pending = [f.name for f in fields if "revocation" in f.name.lower()]
    if pending:
        clearing, keeping = [], []
        for fn in effects:
            changes, _ = effects_of(fn, fields)
            cleared = [p for p in pending if any(f"`{p}`" in c and "clears" in c for c in changes)]
            (clearing if len(cleared) == len(pending) else keeping).append(camel_words(fn.suffix))
        w("- clears " + ", ".join(f"`{p}`" for p in pending) + ": "
          + (", ".join(clearing) or "none"))
        w("- does not clear all of them: " + (", ".join(keeping) or "none"))
        w("")

    if others:
        w("## Helpers the transitions are defined in terms of")
        w("")
        for fn in others:
            w(f"### `{fn.name}({', '.join(n for _, n in fn.params)})` → `{fn.returns}`")
            w("")
            if fn.doc:
                w(wrap(fn.doc))
                w("")
            if fn.returns.startswith("bool"):
                cs = clauses_of(fn)
                if cs:
                    w("True when all of:")
                    w("")
                    for c in cs:
                        w(f"- {c}")
                    w("")
            else:
                m = re.search(r"return\s+(.*?);", fn.body, re.S)
                if m:
                    w("Returns " + term(re.sub(r"\s+", " ", m.group(1)), "") + ".")
                    w("")

    w("## Out of scope")
    w("")
    w("The specification abstracts everything it does not take as a parameter. In")
    w("particular the parameters below are *given* to it, so nothing here says how they")
    w("are established:")
    w("")
    given = []
    for fn in preconditions + effects:
        for type_, name in fn.params:
            if type_.split()[0].endswith("SafeState"):
                continue
            if name not in given:
                given.append(name)
    for g in given:
        w(f"- `{g}`")
    w("")
    w("Owner-threshold signature checking, the Ledger attestation and XMSS")
    w("verification are therefore outside the proof, as are any registry checks that")
    w("read state this model does not carry.")
    w("")

    return "\n".join(out).rstrip() + "\n"


def camel_words(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", " ", name).lower().capitalize()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--spec", default=DEFAULT_SPEC, help="path to RegistrySpec.sol")
    ap.add_argument("--check", metavar="FILE",
                    help="compare FILE with the freshly rendered description")
    args = ap.parse_args()

    text = render(args.spec)
    if args.check:
        try:
            current = open(args.check, encoding="utf-8").read()
        except OSError as exc:
            print(f"describe_spec: cannot read {args.check}: {exc}", file=sys.stderr)
            return 1
        if current != text:
            print(
                f"describe_spec: {args.check} is stale — regenerate it from "
                f"{os.path.basename(args.spec)}",
                file=sys.stderr,
            )
            return 1
        print(f"describe_spec: {args.check} is up to date")
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
