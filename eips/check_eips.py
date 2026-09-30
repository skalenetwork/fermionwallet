#!/usr/bin/env python3
"""Check the EIP drafts: EIP-1 structure, and fidelity to the Solidity they describe.

Two jobs.

*Structure*: the rules the EIP editors' linter (`eipw`) enforces and a reviewer would bounce a
pull request over — preamble keys and their order, title and description lengths, the required
sections in EIP-1's order, the RFC 2119 boilerplate, the exact Copyright line, resolvable links.

*Fidelity*: a specification drifts from its implementation quietly. Every `error` and `event`
declaration, every EIP-712 type string, every interface function signature and every named
constant a draft quotes must exist, byte for byte (modulo whitespace and ‖/||), in the contract
the draft says it describes. A draft that promises an event the code does not emit, or a function
signature nobody can call, fails here rather than in someone's integration.

Usage: python3 eips/check_eips.py [--verbose]
Exit code 0 = clean.
"""
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DRAFTS = "ERCS"

# Preamble keys EIP-1 requires, in the order it requires them. Optional ones in OPTIONAL.
REQUIRED_KEYS = ["eip", "title", "description", "author", "discussions-to", "status", "type",
                 "category", "created"]
OPTIONAL_KEYS = ["requires", "withdrawal-reason"]
SECTIONS = ["Abstract", "Motivation", "Specification", "Rationale", "Backwards Compatibility",
            "Test Cases", "Reference Implementation", "Security Considerations", "Copyright"]
COPYRIGHT = "Copyright and related rights waived via [CC0](../LICENSE.md)."
# EIP-1's key-words paragraph, verbatim (Style Guide → "RFC 2119 and RFC 8174"). Compared
# whitespace-insensitively, since drafts wrap it. "NOT RECOMMENDED" is part of it: the
# RFC 2119-only list, without it, is not what EIP-1 tells authors to insert.
RFC2119 = ('The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", '
           '"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this '
           'document are to be interpreted as described in RFC 2119 and RFC 8174.')
# Absolute links eipw permits. `markdown-relative-links` forbids every other absolute URL —
# including ethereum.org, eips.ethereum.org and ethereum-magicians.org, which must be written
# as relative links or not at all. Transcribed from ethereum/ERCs `config/eipw.toml`.
ALLOWED_LINK_PATTERNS = [
    r"^https://(www\.)?github\.com/ethereum/consensus-specs/(blob|tree)/[a-f0-9]{40}/.+$",
    r"^https://(www\.)?github\.com/ethereum/consensus-specs/commit/[a-f0-9]{40}$",
    r"^https://(www\.)?github\.com/ethereum/execution-specs/(blob|tree)/[a-f0-9]{40}/.+$",
    r"^https://(www\.)?github\.com/ethereum/execution-specs/commit/[a-f0-9]{40}$",
    r"^https://(www\.)?github\.com/ethereum/execution-spec-tests/(blob|tree)/[a-f0-9]{40}/.+$",
    r"^https://(www\.)?github\.com/ethereum/execution-spec-tests/commit/[a-f0-9]{40}$",
    r"^https://(www\.)?github\.com/ethereum/yellowpaper/(blob|tree)/[a-f0-9]{40}/.+$",
    r"^https://(www\.)?github\.com/ethereum/yellowpaper/commit/[a-f0-9]{40}$",
    r"^https://(www\.)?github\.com/ethereum/devp2p/(blob|tree)/[0-9a-f]{40}/.+$",
    r"^https://(www\.)?github\.com/ethereum/devp2p/commit/[0-9a-f]{40}$",
    r"^https://(www\.)?github\.com/ethereum/portal-network-specs/(blob|tree)/[0-9a-f]{40}/.+$",
    r"^https://(www\.)?github\.com/ethereum/portal-network-specs/commit/[0-9a-f]{40}$",
    r"^https://(www\.)?github\.com/bitcoin/bips/(blob|tree)/[0-9a-f]{40}/bip-[0-9]+\.mediawiki$",
    r"^https://(www\.)?github\.com/ChainAgnostic/CAIPs/(blob|tree)/[a-f0-9]{40}/.+$",
    r"^https://(www\.)?github\.com/ChainAgnostic/CAIPs/commit/[0-9a-f]{40}$",
    r"^https://www\.w3\.org/TR/[0-9][0-9][0-9][0-9]/.*$",
    r"^https://[a-z]*\.spec\.whatwg\.org/commit-snapshots/[0-9a-f]{40}/$",
    r"^https://www\.rfc-editor\.org/rfc/.*$",
    r"^https://www\.unicode\.org/reports/tr[0-9]+/tr[0-9]+-[0-9]+\.html$",
    r"^https://(www\.)?github\.com/ethereum/sys-asm/(blob|tree)/[a-f0-9]{40}/.+$",
    r"^https://(www\.)?github\.com/ethereum/sys-asm/commit/[a-f0-9]{40}$",
]
# EIP-1 `author` header: `Name <email>`, `Name (@handle)`, `Name (@handle) <email>` or a bare
# `Name`, comma-separated, and at least one entry must carry a GitHub handle.
AUTHOR_ENTRY = re.compile(r"^[^(<,]+?(?: \(@[A-Za-z0-9-]+\))?(?: <[^@>]+@[^@>]+>)?$")

# Which Solidity each draft is checked against.
SOURCES = {
    "erc-draft-xmss-verification.md": [
        "contracts/lib/xmss-solidity/src/XMSS.sol",
        "contracts/src/XmssVerifier.sol",
        # Its § 6 (leaf-index accounting) is implemented by the registry, not the verifier:
        # the event and the consumption order it prescribes live there.
        "contracts/src/QuantumKeyRegistry.sol",
    ],
    "erc-draft-hash-based-key-registry.md": ["contracts/src/QuantumKeyRegistry.sol"],
    "erc-draft-hybrid-pre-approvals.md": [
        "contracts/src/PreApprovalEngine.sol",
        "contracts/src/FermionGuard.sol",
    ],
}

# Declarations a draft MUST document: dropping one from the draft is drift too, and the
# generic checks below only catch the other direction.
MUST_DOCUMENT = {
    "erc-draft-hash-based-key-registry.md": [
        "registerQuantumKey", "rotateQuantumKey", "requestKeyRevocation", "cancelKeyRevocation",
        "executeKeyRevocation", "isLeafUsed", "registryNonce", "getKey",
        "ApproveQuantumKey(", "RotateQuantumKey(", "QuantumKeyAttestation(", "RequestKeyRevocation(",
        "LeafConsumed", "QuantumKeyRevoked", "LeafAlreadyUsed", "RevocationSuperseded",
    ],
    "erc-draft-hybrid-pre-approvals.md": [
        "createPreApproval", "createPayloadPreApproval", "createAdminPreApproval",
        "revokePreApproval", "validatePreApproval", "getPreApproval", "approvalByTxHash",
        "MIN_WINDOW", "ADMIN_TIMELOCK", "PreApproval(address safe,uint8 approvalClass,",
        "PreApprovalUsed", "NonZeroClassFields",
    ],
    "erc-draft-xmss-verification.md": [
        "verifyXmssSignature", "authPath", "wotsSig", "leafIdx",
    ],
}

errors = []
notes = []


def fail(draft, msg):
    errors.append(f"{draft}: {msg}")


def norm(s):
    """Whitespace-insensitive, ‖-insensitive form for comparing declarations and formulas."""
    return re.sub(r"\s+", "", s.replace("‖", "||").replace("×", "*"))


# ── structure ───────────────────────────────────────────────────────────────


def check_preamble(draft, text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        fail(draft, "no YAML preamble delimited by --- lines")
        return {}
    pre, seen = {}, []
    for line in m.group(1).split("\n"):
        if not line.strip():
            fail(draft, "blank line inside the preamble")
            continue
        km = re.match(r"^([a-z-]+): (.*)$", line)
        if not km:
            fail(draft, f"preamble line is not `key: value`: {line!r}")
            continue
        pre[km.group(1)] = km.group(2).strip()
        seen.append(km.group(1))

    for key in REQUIRED_KEYS:
        if key not in pre:
            fail(draft, f"preamble is missing `{key}`")
    for key in seen:
        if key not in REQUIRED_KEYS + OPTIONAL_KEYS:
            fail(draft, f"unknown preamble key `{key}`")
    order = [k for k in seen if k in REQUIRED_KEYS]
    if order != [k for k in REQUIRED_KEYS if k in order]:
        fail(draft, f"preamble keys out of EIP-1 order: {order}")

    title = pre.get("title", "")
    if len(title) > 44:
        fail(draft, f"title is {len(title)} characters, EIP-1 allows 44: {title!r}")
    if title != title.strip() or title.endswith("."):
        fail(draft, "title must not be padded or end with a period")
    for word in ("standard", "eip", "erc"):
        if re.search(rf"\b{word}\b", title, re.I):
            fail(draft, f"title must not contain {word!r}")

    desc = pre.get("description", "")
    if len(desc) > 140:
        fail(draft, f"description is {len(desc)} characters, EIP-1 allows 140")
    if desc.endswith("."):
        fail(draft, "description must not end with a period")
    if re.search(r"\bstandard\b", desc, re.I):
        fail(draft, "description must not contain 'standard'")
    if title and title.lower() in desc.lower():
        fail(draft, "description must not repeat the title")

    author = pre.get("author", "")
    entries = [e.strip() for e in author.split(",")] if author else []
    if not entries or not all(AUTHOR_ENTRY.match(e) for e in entries):
        fail(draft, f"author must be a comma-separated list of `Name`, `Name <email>`, "
                    f"`Name (@handle)` or `Name (@handle) <email>`, got {author!r}")
    elif not any("(@" in e for e in entries):
        fail(draft, "at least one author must give a GitHub username (EIP-1 `author` header)")
    if pre.get("status") != "Draft":
        fail(draft, f"status must be Draft while unsubmitted, got {pre.get('status')!r}")
    if pre.get("type") != "Standards Track":
        fail(draft, f"type must be 'Standards Track', got {pre.get('type')!r}")
    if pre.get("category") != "ERC":
        fail(draft, f"category must be ERC, got {pre.get('category')!r}")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", pre.get("created", "")):
        fail(draft, "created must be an ISO yyyy-mm-dd date")
    if "requires" in pre:
        nums = [n.strip() for n in pre["requires"].split(",")]
        if not all(n.isdigit() for n in nums):
            fail(draft, f"requires must be EIP numbers, got {pre['requires']!r}")
        elif [int(n) for n in nums] != sorted(int(n) for n in nums):
            fail(draft, "requires must be in ascending order")
    if pre.get("eip") != "<to be assigned>":
        notes.append(f"{draft}: eip is {pre.get('eip')!r} — assign it only at submission")
    return pre


def check_sections(draft, text):
    found = re.findall(r"^## (.+)$", text, re.M)
    required = [s for s in found if s in SECTIONS]
    if required != [s for s in SECTIONS if s in required]:
        fail(draft, f"sections out of EIP-1 order: {required}")
    for s in SECTIONS:
        if s not in found:
            fail(draft, f"missing required section `## {s}`")
    for s in found:
        if s not in SECTIONS:
            fail(draft, f"unexpected top-level section `## {s}` (EIP-1 fixes the set)")
    if norm(RFC2119) not in norm(text):
        fail(draft, "the RFC 2119 / RFC 8174 key-words paragraph is missing or is not EIP-1's "
                    "wording (it lists MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, "
                    "SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY and OPTIONAL)")
    if COPYRIGHT not in text:
        fail(draft, f"Copyright section must contain exactly: {COPYRIGHT}")


def check_links(draft, path, text):
    for target in re.findall(r"\]\((\S+?)\)", text):
        if target.startswith(("http://", "https://")):
            if not any(re.match(p, target) for p in ALLOWED_LINK_PATTERNS):
                fail(draft, f"absolute link eipw's `markdown-relative-links` rejects: {target}")
        elif target.startswith("#"):
            continue
        else:
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
            if not os.path.exists(resolved):
                fail(draft, f"relative link does not resolve: {target}")


# ── fidelity to the Solidity ────────────────────────────────────────────────


def solidity_declarations(sources):
    """Collect from the contracts: declarations, canonical function signatures, type strings."""
    flat = ""
    for src in sources:
        with open(os.path.join(REPO, src)) as f:
            body = f.read()
        body = re.sub(r"//[^\n]*", "", body)          # line comments (incl. /// docs)
        body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
        flat += "\n" + body

    collapsed = re.sub(r"\s+", " ", flat)
    decls = set()
    for kind in ("error", "event"):
        for m in re.finditer(rf"\b{kind} (\w+)\s*\(([^;]*?)\)\s*;", collapsed):
            decls.add(norm(f"{kind} {m.group(1)}({m.group(2)});"))

    sigs = {}   # name -> set of canonical "name(type,type)"

    def add_sig(name, params):
        types = []
        for p in [p for p in params.split(",") if p.strip()]:
            tokens = p.replace("(", " ( ").split()
            types.append(tokens[0])
        sigs.setdefault(name, set()).add(f"{name}({','.join(types)})")

    for m in re.finditer(r"\bfunction (\w+)\s*\(([^)]*)\)", collapsed):
        add_sig(m.group(1), m.group(2))
    # Auto-generated getters: public mappings (possibly nested, so the closing paren has to be
    # found by balancing rather than by regex), constants and immutables.
    for m in re.finditer(r"\bmapping\(", collapsed):
        depth, i = 1, m.end()
        while i < len(collapsed) and depth:
            depth += {"(": 1, ")": -1}.get(collapsed[i], 0)
            i += 1
        tail = re.match(r"\s+public\s+(\w+)\s*;", collapsed[i:])
        if not tail:
            continue
        keys = re.findall(r"(\w+)[^=>()]*=>", collapsed[m.end():i - 1])
        add_sig(tail.group(1), ",".join(keys))
    for m in re.finditer(r"\b(u?int\d*|address|bytes32|bool)\s+public\s+(?:constant|immutable)\s+(\w+)", collapsed):
        add_sig(m.group(2), "")

    type_strings = set(re.findall(r'"([A-Z]\w+\([^"]*\))"', flat))
    constants = {m.group(1): m.group(2).strip()
                 for m in re.finditer(r"\b\w+\s+(?:internal|private|public)\s+constant\s+(\w+)\s*=\s*([^;]+);", collapsed)}
    return decls, sigs, type_strings, constants, norm(flat)


def check_fidelity(draft, text, sources):
    decls, sigs, type_strings, constants, flat_norm = solidity_declarations(sources)
    text_norm = norm(text)

    # 1. Every error/event declaration the draft quotes must exist in the code.
    for kind in ("error", "event"):
        for m in re.finditer(rf"^\s*{kind} (\w+)\s*\(([^;]*?)\)\s*;", text, re.M | re.S):
            want = norm(f"{kind} {m.group(1)}({m.group(2)});")
            if want not in decls:
                fail(draft, f"{kind} declaration is not in the contracts: {m.group(1)}(...)")

    # 2. Every function the draft's interfaces declare must be callable on the reference.
    for m in re.finditer(r"^\s*function (\w+)\s*\(([^)]*)\)", text, re.M | re.S):
        name, params = m.group(1), m.group(2)
        types = []
        for p in [p for p in params.split(",") if p.strip()]:
            types.append(p.split()[0])
        want = f"{name}({','.join(types)})"
        if name not in sigs:
            fail(draft, f"function `{name}` does not exist in the contracts")
        elif want not in sigs[name]:
            fail(draft, f"signature drift: draft has {want}, contracts have {sorted(sigs[name])}")

    # 3. Every EIP-712 type string the draft quotes must be the one the contracts hash.
    for quoted in re.findall(r"^([A-Z]\w+\((?:address|uint|bytes|bool|string)[^\n]*\))$", text, re.M):
        if quoted not in type_strings:
            fail(draft, f"EIP-712 type string is not in the contracts: {quoted[:60]}…")

    # 4. Named constants and formulas quoted in prose.
    for name, value in constants.items():
        if name in text and value.isdigit() and f"={value}" not in norm(text):
            # Only flag numeric constants the draft actually names with a number nearby.
            if not re.search(rf"{name}[^\n]*\b{value}\b", text):
                fail(draft, f"constant {name} is quoted without its value {value}")

    # 5. Fragments that must appear verbatim (the other drift direction).
    for fragment in MUST_DOCUMENT.get(draft, []):
        if norm(fragment) not in text_norm:
            fail(draft, f"draft no longer documents {fragment!r}")

    return flat_norm


def check_labels(drafts):
    """Every [XV-nn]/[KR-nn]/[PA-nn] citation must name a clause some draft defines.

    The drafts cite each other's clauses (the registry requires the verification ERC's leaf
    rules), so the label space is shared; a citation of a clause that was renumbered or dropped
    is a broken normative reference, which is the kind of thing reviewers find and authors do
    not.
    """
    prefix_of = {"XV": "erc-draft-xmss-verification.md",
                 "KR": "erc-draft-hash-based-key-registry.md",
                 "PA": "erc-draft-hybrid-pre-approvals.md"}
    defined, cited = {}, {}
    for draft, text in drafts.items():
        defined[draft] = set(re.findall(r"\*\*\[([A-Z]{2}-\d+)\]\*\*", text))
        cited[draft] = set(re.findall(r"\[([A-Z]{2}-\d+)\]", text))
    for draft, labels in cited.items():
        for label in sorted(labels):
            prefix = label.split("-")[0]
            home = prefix_of.get(prefix)
            if home is None:
                fail(draft, f"citation {label} uses an unknown clause prefix")
            elif label not in defined.get(home, ()):
                fail(draft, f"citation {label} names a clause {home} does not define")
    for draft, labels in defined.items():
        nums = sorted(int(l.split("-")[1]) for l in labels)
        if nums != list(range(1, len(nums) + 1)):
            missing = [n for n in range(1, max(nums) + 1) if n not in nums]
            fail(draft, f"clause numbering has gaps: {missing}")


def check_type_hashes(draft, text, sources):
    """A draft that quotes a type hash as a literal must quote the right one.

    Needs `cast` (Foundry) for keccak256; skipped with a note when it is unavailable, since
    the drafts' other checks do not depend on a toolchain.
    """
    claimed = [m.group(1) for m in re.finditer(r"type hash is\s*\n?`(0x[0-9a-f]{64})`", text)]
    if not claimed:
        return
    cast = shutil.which("cast") or os.path.expanduser("~/.foundry/bin/cast")
    if not os.path.exists(cast):
        notes.append(f"{draft}: type-hash literals not verified (no `cast` on PATH)")
        return
    _, _, type_strings, _, _ = solidity_declarations(sources)
    hashes = {}
    for ts in type_strings:
        out = subprocess.run([cast, "keccak", ts], capture_output=True, text=True)
        hashes[out.stdout.strip()] = ts
    for literal in claimed:
        if literal not in hashes:
            fail(draft, f"quoted type hash {literal} is not the keccak256 of any type string "
                        f"the contracts use")


def check_xmss_specifics(draft, text, flat_norm):
    """The hash instantiation and wire format the verification draft states normatively."""
    for formula in ["PRF(SEED,ADRS)=SHA-256(toByte(3,32)||SEED||ADRS)",
                    "F(KEY,M)=SHA-256(toByte(0,32)||KEY||M)",
                    "H(KEY,M)=SHA-256(toByte(1,32)||KEY||M)",
                    "H_msg(KEY,M)=SHA-256(toByte(2,32)||KEY||M)"]:
        if formula not in norm(text):
            fail(draft, f"missing the hash instantiation: {formula}")
    if "2304+32*h" not in norm(text).replace("32*treeHeight", "32*h"):
        fail(draft, "missing the encoded-signature length formula 2304 + 32 * h")
    for value in ("2624", "2816", "2944"):
        if value not in text:
            fail(draft, f"missing the encoded length {value} for a standardised height")
    if "0x5867b896" not in text:
        fail(draft, "missing the IXmssVerifier ERC-165 interface identifier")
    # The numbers that define the parameter family, as the library declares them.
    for decl in ("LEN=67", "LEN1=64", "W_MINUS_1=15", "MAX_HEIGHT=20"):
        if decl not in flat_norm:
            fail(draft, f"the library no longer declares {decl} — the draft's §1 table is stale")


def main():
    verbose = "--verbose" in sys.argv
    texts = {}
    drafts = sorted(f for f in os.listdir(os.path.join(HERE, DRAFTS)) if f.endswith(".md"))
    if not drafts:
        sys.exit("no drafts found")
    for draft in drafts:
        path = os.path.join(HERE, DRAFTS, draft)
        with open(path) as f:
            text = f.read()
        texts[draft] = text
        if draft not in SOURCES:
            fail(draft, "no contracts listed in SOURCES — fidelity cannot be checked")
            continue
        check_preamble(draft, text)
        check_sections(draft, text)
        check_links(draft, path, text)
        flat_norm = check_fidelity(draft, text, SOURCES[draft])
        check_type_hashes(draft, text, SOURCES[draft])
        if draft == "erc-draft-xmss-verification.md":
            check_xmss_specifics(draft, text, flat_norm)
        if verbose:
            print(f"checked {draft} ({len(text.splitlines())} lines) "
                  f"against {', '.join(SOURCES[draft])}")

    check_labels(texts)

    for note in notes:
        print(f"note: {note}")
    if errors:
        print(f"\n{len(errors)} problem(s):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        sys.exit(1)
    print(f"{len(drafts)} drafts: preamble, sections, links and fidelity to the contracts all OK")


if __name__ == "__main__":
    main()
