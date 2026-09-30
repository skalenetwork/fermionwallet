#!/usr/bin/env python3
"""Two defects in the app's FermionWallet support, demonstrated against the app.

This file is an exhibit, not a regression suite. Each check asserts that a defect
is *present*, so a run that prints `all checks passed` means every defect is still
there; once one is fixed its check turns red and says so. Run it beside the other
suites — it takes ports and a container name of its own.

    ledger-app/test/test_review_gaps.py     # expects the ELF built by build.sh
    REVIEW_GAPS_PORTS=15041,19941 ...       # if those two are taken

## A. The Guard binding is keyed on a field the human is never shown

`main.rs::review_and_digest` binds a key slot to
`KIND_GUARD ‖ chainId ‖ fields.verifying_contract()` and `wallet.rs::commit_binding`
writes that to NVM, permanently, on the first approved signature. But
`review_pre_approval` renders Safe, Network, Policy and Binding — never
`verifyingContract`. So the one field that decides what the slot is married to for
the rest of its life is invisible at the moment of consent.

A host that swaps `verifyingContract` for an address of its own therefore gets a
routine-looking approval — every page the holder reads is the real transfer — and
spends the slot's identity on that address. Every later pre-approval for the real
Guard is refused with `0x6A81`. This build has `MAX_KEYS = 1` and no key-generation
or retire command, so nothing on the APDU surface can undo it: the registered
`xmssRoot` is dead and the remaining leaves are unreachable.

The forged signature itself is worthless (the real Guard hashes a different domain),
so this destroys availability, not funds. It costs one leaf and the key.

## B. `fmt.rs::push_utc` truncates the year, so an unbounded window reads as a date

`push_utc` ends with `self.push_u32(year as u32)`. A `uint64 validUntil` reaches
year 584-billion, so the cast wraps, and for every plausible date there is a huge
`validUntil` that renders the same string, character for character:

    validUntil =          1790769600  ->  "30 Sep 2026 12:00 UTC"   (really 2026)
    validUntil = 135536078592187200  ->  "30 Sep 2026 12:00 UTC"   (really 4294969322)

The digest covers the real value. `fermionwallet.md` FWL-036 says a signed transfer
stays relayable by anyone until `validUntil` with no cancel path, and that "short
windows are the only control" — this turns the control off while displaying it as on.
The wallet flow is the caller that matters, but `valid_from`/`valid_to` on the Safe
review go through the same function.

What that is worth to a host: the holder cannot tell a transfer that expired unrelayed
from one still live, so once the displayed date has passed they sign a replacement —
and both are relayable. The amount goes out twice. It is not a window problem, it is a
double spend of the thing the window was supposed to bound.

## C. Not shown here: nothing in either suite pins the counter-before-signature order

Speculos keeps NVM in RAM, so no host-side test can see whether the commit landed
before the signature was computed. Moving `consume_leaf` and `commit_binding` to
*after* `BLOB_READY = true` in `main.rs::sign_pre_approval` leaves `test_wallet.py`
at 23/23 and `test_app.py` at 29/29, though both docstrings claim to check it.
Likewise, hiding `Amount`, `Recipient` and `Network` from `wallet.rs::review`, and
writing the binding before the review instead of after it, each pass 23/23.
Those are test gaps, not device behaviour, so they belong in the review, not here.
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "demo"))

import test_app as base  # noqa: E402  (the shared harness: check, decide, cast)
from test_app import CHAIN_ID, FIELDS, GUARD, SEED, check, decide  # noqa: E402
from test_wallet import TRANSFER, WALLET, sign_transfer, transfer_digest  # noqa: E402

ELF = os.path.join(REPO, "ledger-app", "build", "nanos2", "bin", "app.elf")

# An address the holder has never heard of, chosen so its hex is recognisable in a
# screen dump even through Speculos' scrolling BAGL lines.
ATTACKER_GUARD = "0xBaDbaDbaDBAdbaDbAdBAdBadbADbADBadBAd0001"

# A date the holder would accept, and a `uint64` that prints identically.
HONEST_UNTIL = 1790769600           # 30 Sep 2026 12:00:00 UTC
FOREVER_UNTIL = 135536078592187200  # 30 Sep 4294969322 12:00:00 UTC

SW_WRONG_BINDING = 0x6A81


class Device:
    """The built app in Speculos, on a container and ports of its own.

    Not test_app.py's launcher, which fixes both ports and the container name: this
    file has to be runnable while those suites are running.
    """

    def __init__(self):
        api, apdu = os.environ.get("REVIEW_GAPS_PORTS", "15041,19941").split(",")
        self.api, self.apdu = int(api), int(apdu)
        self.container = None

    def start(self):
        if not os.path.exists(ELF):
            sys.exit(f"no app at {ELF} — run ledger-app/build.sh first")
        self.container = f"fg-review-gaps-{os.getpid()}-{int(time.time())}"
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", self.container,
             "-v", os.path.dirname(ELF) + ":/app",
             "-p", f"{self.api}:5000", "-p", f"{self.apdu}:9999",
             "ghcr.io/ledgerhq/speculos:latest", "--model", "nanosp", "--display", "headless",
             "--api-port", "5000", "--apdu-port", "9999", "--seed", SEED, "/app/app.elf"],
            check=True, capture_output=True)
        os.environ["SPECULOS_APDU_URL"] = f"tcp://127.0.0.1:{self.apdu}"
        os.environ["SPECULOS_API_URL"] = f"http://127.0.0.1:{self.api}"

        import ledger_device as ld
        device = ld.Device(ld.transport())
        for _ in range(60):
            try:
                device.next_leaf()
                return device
            except Exception:  # noqa: BLE001 (the emulator is simply not up yet)
                time.sleep(1)
        sys.exit("the app never answered in Speculos")

    def stop(self):
        if self.container:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)
            os.environ.pop("SPECULOS_APDU_URL", None)
            os.environ.pop("SPECULOS_API_URL", None)
            self.container = None
            time.sleep(1)  # let the ports come free before the next container


def home_carousel(transport, pages=12):
    """Every distinct page of the home screen, walked with the right button."""
    seen, out = set(), []
    for _ in range(pages):
        page = tuple(transport.screen())
        if page and page not in seen:
            seen.add(page)
            out.append(" ".join(page))
        transport.press("right")
        time.sleep(0.25)
    return out


def flatten(screens):
    # Speculos reports a scrolling BAGL line from wherever it had got to, so join
    # everything and strip the separators a grouped number introduces.
    return " ".join(" ".join(lines) for lines in screens).replace(",", "")


def finding_a(emu):
    """A host-chosen `verifyingContract`, never displayed, permanently claims the key."""
    device = emu.start()
    try:
        before = home_carousel(device.tr)
        check("A0: a fresh slot reports itself unbound on the home screen",
              any("not used yet" in p for p in before), str(before))

        # Walking the carousel left the menu somewhere in the middle, and any APDU
        # rebuilds it at page 0. Without this, `decide` can read a home page that
        # test_app.HOME_PAGES does not list, take it for a review, and give up.
        device.next_leaf()

        screens = []
        walker = decide(device.tr, "approve", screens)
        signed = device.sign_preapproval(FIELDS, CHAIN_ID, ATTACKER_GUARD, timeout=90)
        walker.join(timeout=15)
        check("A1: the device signs a pre-approval for a verifyingContract of the host's choosing",
              signed.get("status") == "approved", str(signed))

        seen = flatten(screens).lower()
        check("A2: and shows the holder no page carrying that address — the consent is blind",
              "badbad" not in seen, seen[:400])
        check("A3: the pages it does show are the genuine transfer, so nothing looks wrong",
              all(f in seen.lower() for f in ("token", "amount", "recipient", "safe", "network")),
              seen[:400])

        after = home_carousel(device.tr)
        check("A4: the slot is now married to that address, and says so only afterwards",
              any("badb" in p.lower() for p in after), str(after))

        leaf = device.next_leaf()
        import ledger_device as ld
        try:
            device.sign_preapproval(FIELDS, CHAIN_ID, GUARD, timeout=8)
            check("A5: the real Guard is refused for the rest of the key's life", False,
                  "it signed for the real Guard after all")
        except ld.DeviceError as e:
            check("A5: the real Guard is refused for the rest of the key's life",
                  "belongs to a different contract" in str(e), str(e))
        except (TimeoutError, OSError):
            check("A5: the real Guard is refused for the rest of the key's life", False,
                  "the device drew a review instead")
        check("A6: with no key-generation or retire command to undo it, and a leaf already spent",
              device.next_leaf() == leaf and leaf == 1, f"leaf {leaf}")
    finally:
        emu.stop()


def finding_b(emu):
    """Two `validUntil` values 4 billion years apart, one screen."""
    device = emu.start()
    try:
        rendered = {}
        for label, until in (("honest", HONEST_UNTIL), ("forever", FOREVER_UNTIL)):
            fields = dict(TRANSFER, validUntil=until)
            screens = []
            walker = decide(device.tr, "approve", screens)
            result = sign_transfer(device, WALLET, fields, CHAIN_ID, chunks=1, timeout=90)
            walker.join(timeout=15)
            pages = [" ".join(p) for p in screens if "UTC" in " ".join(p)]
            check(f"B0 ({label}): the review carries a Valid-until page", bool(pages), str(screens))
            rendered[label] = pages[0] if pages else None
            # The digest covers the `validUntil` that was *sent*, whatever the screen
            # drew — recomputed with `cast` from the spec's own type string.
            want = transfer_digest(WALLET, fields, result["leaf"])
            check(f"B1 ({label}): the digest covers the validUntil sent, not the one drawn",
                  result["digest"].lower() == want.lower(),
                  f"device {result['digest']} vs cast {want}")

        check("B2: a validUntil of year 4,294,969,322 renders exactly like one in 2026",
              rendered["honest"] is not None and rendered["honest"] == rendered["forever"],
              f"honest {rendered['honest']!r} vs forever {rendered['forever']!r}")
        check("B3: so FWL-036's only control — a short window — cannot be read off the screen",
              rendered["honest"] == rendered["forever"] and "2026" in (rendered["honest"] or ""),
              str(rendered))
    finally:
        emu.stop()


def main():
    emu = Device()
    try:
        finding_a(emu)
        finding_b(emu)
    finally:
        emu.stop()

    if base.failures:
        print("\nno longer reproducible: " + ", ".join(base.failures))
        return 1
    print("\nall checks passed — both defects are still present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
