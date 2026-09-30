#!/usr/bin/env python3
"""The host, the device and the relayer must agree about the wire.

Three components carry the same protocol in three languages: the app dispatches on
instruction bytes (`ledger-app/src/main.rs`), the host names them as constants
(`demo/ledger_device.py`), and two documents restate them (`ledger-app/README.md`,
`demo/LEDGER.md`). The relayer, `contracts/script/Demo.s.sol`, carries the signature
blob's shape. Nothing links them: a number can change in one place and stay wrong
everywhere else until a signature is produced, which happens late and costs a one-time
XMSS leaf.

That is not hypothetical. Twice today the three disagreed:

  - the simulator prepended the public root and SEED to every signature and the device
    did not, so every hardware-signed approval died on a length check in the relayer —
    *after* the device had committed its counter and spent a leaf;
  - renumbering the instructions to match Ledger's Ethereum app touched seven files, and
    a host left on the old numbers reported nothing more useful than `refused (0x6e01)`.

So: one check, run in CI, that the numbers and the blob arithmetic agree everywhere.

    python3 demo/check_wire_protocol.py
    python3 demo/check_wire_protocol.py --list    # print what it found, and where
"""
import os
import re
import subprocess
import sys

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                      capture_output=True, text=True, check=True).stdout.strip()

# `INS_GET_XMSS_ROOT = 0x44` in the host.
HOST_INS = re.compile(r"^INS_(?P<name>[A-Z_]+)\s*=\s*0x(?P<value>[0-9A-Fa-f]{2})\s*$", re.M)
# The app's dispatcher is a match over `(ins, p1, slot_ok)`. An arm may answer inline —
# `(0x44, 0, true) => Ok(Ins::GetXmssRoot)` — or open a block and answer a few lines
# later, and its guard may itself contain parentheses (`p1 @ (P1_FIRST | P1_MORE)`). So
# the arm's number is taken from the line, and its variant from the next few lines. Arms
# that list several numbers before the comma are the catch-alls that answer `Err`.
ARM_START = re.compile(r"^\s*\(\s*0x(?P<value>[0-9A-Fa-f]{2})\s*,")
ARM_VARIANT = re.compile(r"Ok\(Ins::(?P<name>\w+)")

def key(name):
    """`GET_XMSS_ROOT` and `GetXmssRoot` are the same command; so are `SIGN_PREAPPROVAL`
    and `SignPreApproval`, which differ in more than case in the middle."""
    return name.replace("_", "").lower()


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def app_instructions():
    lines = read("ledger-app/src/main.rs").splitlines()
    found = {}
    for i, line in enumerate(lines):
        m = ARM_START.match(line)
        if not m or "|" in line.split(",", 1)[0]:   # a catch-all over several numbers
            continue
        for ahead in lines[i:i + 5]:
            v = ARM_VARIANT.search(ahead)
            if v:
                found.setdefault(v.group("name"), int(m.group("value"), 16))
                break
    return found


def instruction_numbers():
    host = {m.group("name"): int(m.group("value"), 16) for m in HOST_INS.finditer(read("demo/ledger_device.py"))}
    return host, app_instructions()


def check_instructions(problems, verbose):
    host, app = instruction_numbers()
    if not host or not app:
        problems.append("could not find instruction constants — did the dispatcher or the host change shape?")
        return
    by_key = {key(n): (n, v) for n, v in app.items()}
    for name, value in sorted(host.items()):
        found = by_key.get(key(name))
        if found is None:
            problems.append(f"the host defines INS_{name} = 0x{value:02x}; the app dispatches nothing that matches")
        elif found[1] != value:
            problems.append(
                f"INS_{name}: the host says 0x{value:02x}, the app dispatches Ins::{found[0]} on 0x{found[1]:02x}"
            )
        elif verbose:
            print(f"  0x{value:02x}  {name}  <->  Ins::{found[0]}")

    # Every number the host uses must also be written correctly in both documents, since
    # those are what a reader implements against.
    for rel in ("ledger-app/README.md", "demo/LEDGER.md"):
        text = read(rel)
        for name, value in sorted(host.items()):
            # A command's number is written immediately before its name, in a table row or
            # a bullet: "| `0x44` | `GET_XMSS_ROOT` |". Deliberately tight — a loose window
            # matches the status words that also live in these documents.
            for m in re.finditer(r"`?0x(?P<v>[0-9A-Fa-f]{2})`?[ |`]{1,6}" + re.escape(name) + r"\b", text):
                if int(m.group("v"), 16) != value:
                    line = text[: m.start()].count("\n") + 1
                    problems.append(
                        f"{rel}:{line}: {name} is documented as 0x{m.group('v')}, but the host and app use 0x{value:02x}"
                    )


def check_blob_shape(problems, verbose):
    """The signature blob: `r ‖ wotsSig[67] ‖ authPath[h] ‖ ecdsa(65)`, with the ECDSA
    half LAST so a host reading only the first chunk cannot obtain one half without the
    other. Three places encode that, in three ways."""
    app = read("ledger-app/src/xmss.rs") + read("ledger-app/src/main.rs")
    sim = read("demo/ledger_sim.py")
    host = read("demo/ledger_device.py")
    relayer = read("contracts/script/Demo.s.sol")

    # The simulator builds the blob explicitly; the order of the concatenation is the
    # statement. `r + wots + auth` with no root/seed prefix, and no ecdsa in it.
    if not re.search(r"blob\s*=\s*r\s*\+\s*b?\"?\"?\.?join|blob\s*=\s*r\s*\+", sim):
        problems.append("demo/ledger_sim.py: could not find the blob assembly — has its shape changed?")
    elif re.search(r"blob\s*=\s*_levels|blob\s*=\s*.*_seed\s*\+\s*r", sim):
        problems.append(
            "demo/ledger_sim.py prepends the public key to the signature blob; the device does not, "
            "and the relayer will reject every hardware signature on length"
        )

    # The host splits the blob. It must take the ECDSA half from the END.
    if "blob[:65]" in host and "blob[65:]" in host:
        problems.append(
            "demo/ledger_device.py splits the ECDSA half off the FRONT (blob[:65]); the app now puts it last, "
            "so the two halves would be silently transposed — same total length, no length check catches it"
        )

    # The relayer's word arithmetic must still be `firstWord + 1 + 67 + H`.
    if not re.search(r"blob\.length\s*==\s*32\s*\*\s*\(firstWord\s*\+\s*1\s*\+\s*67\s*\+\s*H\)", relayer):
        problems.append(
            "contracts/script/Demo.s.sol: the blob length check is not `32 * (firstWord + 1 + 67 + H)` — "
            "the decoder and the device may no longer agree about the layout"
        )
    elif verbose:
        print("  relayer expects 32 * (firstWord + 1 + 67 + H) words")

    if "SIG_LEN" in app and verbose:
        print("  app defines SIG_LEN for the XMSS half")


def main():
    verbose = "--list" in sys.argv
    problems = []
    check_instructions(problems, verbose)
    check_blob_shape(problems, verbose)
    if problems:
        print(f"{len(problems)} disagreement(s) about the wire protocol:")
        for p in problems:
            print(f"  {p}")
        return 1
    host, _ = instruction_numbers()
    print(f"wire protocol: {len(host)} instructions agree across the app, the host and both documents; "
          "blob layout consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
