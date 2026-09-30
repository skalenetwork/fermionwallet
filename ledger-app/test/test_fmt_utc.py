#!/usr/bin/env python3
"""The screen must not say less than the payload: `fmt.rs`'s two ways of lying.

A regression suite for one funds-losing defect and one of its relatives.

## What went wrong

`fmt.rs::push_utc` ended with `push_u32(year as u32)` while the timestamp it formats
is a `uint64`. The year wrapped at 2^32, so every plausible date had an enormous twin
that rendered character for character the same — on the device, approved and signed:

    validUntil =         1790769600  ->  "30 Sep 2026 12:00 UTC"   (really 2026)
    validUntil = 135536078592187200  ->  "30 Sep 2026 12:00 UTC"   (really 4294969322)

and the digest covered the value that was sent, not the one drawn.

`fermionwallet.md` [FWL-036] makes a signed transfer relayable by anyone until
`validUntil`, with no cancel path, and says short windows are the only control there
is. This turned that control off while displaying it as on, and the loss is not a
long window: it is a double spend. The holder signs, the transfer is not relayed, the
date on the screen passes, the holder signs a replacement believing the first is
dead — and the relayer submits both. The amount leaves the wallet twice. The same
function draws `validFrom`/`validTo` on the Safe pre-approval review, so the Guard
product carried it too.

`Buf::overflowed` is the same class of bug one step away: a field that did not fit
its buffer used to render as the prefix that did, and nothing read the flag. Both
reviews now ask it once, after their last field, and answer `0x6A80` rather than draw
a page that says less than the payload.

And the flag only ever covered half the problem, because a `Buf` can be well within
its capacity and still be cut in half by the widget it is handed to. The SDK's `Page`
draws three lines of seventeen characters and drops the rest with no mark at all, so
the home screen's `Key is for` — a 64-character string in a 128-byte buffer — lost its
chain id on every device this app has ever run on, untainted and unflagged. `fmt.rs`
cannot see that; only the caller can. D4 checks the shape that fixes it.

## What is checked

Host, against `src/fmt.rs` compiled on its own — no device needed, runs in seconds:

* every renderable timestamp draws what Python's own `datetime` says it should, over
  a spread of two hundred values and the awkward ones (epoch, leap days, the 1900/2100
  century rules, both sides of the boundary);
* `MAX_UTC_SECS` is exactly the last second `datetime` itself can represent;
* each of those dates' wrapped twin — the timestamp the old cast drew identically —
  is refused and renders differently from the honest one;
* a field that overflows its buffer reads `TOO_LONG`, never its own prefix, and the
  taint survives `clear()` so one review-wide check sees it.

Device, in Speculos, on ports and a container of this file's own. `push_utc`'s own
advice is to refuse such a timestamp *before* the review rather than put `NOT_A_DATE`
in front of the holder, and `main.rs::review_and_digest` now does: both arms ask
`fmt::utc_renderable` among the pre-checks that answer `0x6A80` before a single
screen. So on the device the marker is unreachable — which is the point of it, and
why the checks below read the refusal rather than the page:

* D1 a Safe pre-approval whose `validTo` is a wrapped twin: no review is drawn at
  all, neither Valid-to nor Valid-from, the answer is `0x6A80` and not the status
  word for a human's rejection, and it costs no leaf;
* D2 a transfer with a plausible `validUntil` still reviews and signs exactly as
  before, digest confirmed against `cast` — the fix must not break the normal path;
* D3 the same transfer with the wrapped twin: refused unseen, no page, no leaf;
* D4 the widest value the app can draw, `chainId = 2^256 - 1`: 103 characters, drawn
  whole on the review page that paginates and nowhere near a home-screen `Page`,
  which draws three lines of seventeen characters and drops the rest unmarked.

## Running it

    ledger-app/test/test_fmt_utc.py              # host checks, then Speculos
    ledger-app/test/test_fmt_utc.py --host       # host checks only
    FMT_UTC_PORTS=15071,19971 ...                # if those two are taken
    FMT_UTC_ELF=/path/app.elf ...                # an ELF built somewhere else

## Falsifying it

A test that passes against the broken build is worth nothing, so the inverse of each
fix is a flag. Each one must turn the suite red:

    ledger-app/test/test_fmt_utc.py --host --mutate wrap-year
    ledger-app/test/test_fmt_utc.py --host --mutate show-prefix
    ledger-app/test/test_fmt_utc.py --host --mutate forget-taint

`wrap-year` restores `push_u32(year as u32)` with no guard — the defect itself.
`show-prefix` puts the truncated prefix back in `as_str`. `forget-taint` makes
`clear()` reset the flag, so a review-wide check stops seeing anything. The mutation
patches a *copy* of `fmt.rs` in a temporary directory; the file in the tree is not
touched.

The device checks are falsified differently now that they read the gate rather than
the marker: mutating `fmt.rs` alone no longer reaches them, because the payload is
refused before `push_utc` is ever called. Build an app with the two
`fmt::utc_renderable` clauses removed from `main.rs::review_and_digest` and point
`FMT_UTC_ELF` at it — D1a/D1b/D1c, D3a/D3c and D5b/D5c must all go red, because that
app draws the review and answers `0x6985` when the walker rejects it. That is the
build this suite's device half was first written against, and it is exactly what the
gate is there to prevent.
"""
import argparse
import datetime
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
FMT_RS = os.path.join(REPO, "ledger-app", "src", "fmt.rs")
ELF = os.environ.get("FMT_UTC_ELF", os.path.join(REPO, "ledger-app", "build", "nanos2", "bin", "app.elf"))

sys.path.insert(0, os.path.join(REPO, "demo"))

# ── the app's APDU surface, in one place ─────────────────────────────────────
#
# Every instruction number, P1 and status word this file uses comes from
# `demo/ledger_device.py`, the host half of this app's protocol: when the numbering
# changes, that file changes with it and so does this test. No APDU number is written
# out anywhere below, and the signature blob is never parsed here — nothing in this
# suite depends on the order of the two halves.
from ledger_device import (  # noqa: E402
    CHUNK, CLA, INS_GET_LEAF_INDEX, INS_SIGN_PREAPPROVAL, P1_FIRST, P1_LAST, P1_MORE,
    SW_BAD_FIELDS, SW_DENIED, SW_OK, encode_payload, transport,
)

SEED = "test test test test test test test test test test test junk"
SPECULOS_IMAGE = os.environ.get("SPECULOS_IMAGE", "ghcr.io/ledgerhq/speculos:latest")
BUILDER_IMAGE = os.environ.get(
    "LEDGER_APP_BUILDER", "ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest")
API_PORT, APDU_PORT = (int(p) for p in os.environ.get("FMT_UTC_PORTS", "15071,19971").split(","))
KEY_SLOT = 1  # this build has one

# ── the payloads ─────────────────────────────────────────────────────────────

CHAIN_ID = 31337
GUARD = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
WALLET = "0xCf7Ed3AcCa5a467e9e704C703E8D87F634fB0Fc9"
DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
TRANSFER_TYPE = (
    "Transfer(address wallet,address token,address to,uint256 amount,uint32 leafIndex,"
    "uint64 validUntil)"
)
TRANSFER = {
    "token": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "to": "0x000000000000000000000000000000000000dEaD",
    "amount": str(125 * 10**18),
    "validUntil": 1790769600,  # 30 Sep 2026 12:00:00 UTC
}
PRE_APPROVAL = {
    "safe": "0x8E3fd7B315486ce7Ea44A6E5129046148f807D49", "approvalClass": 0,
    "token": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "recipient": "0x000000000000000000000000000000000000dEaD",
    "amount": str(250 * 10**18), "target": "0x" + "00" * 20, "value": "0",
    "dataHash": "0x" + "00" * 32, "validFrom": 1790000000, "validTo": 1790086400,
    "nonce": "0x" + "11" * 32, "quantumKeyId": "0x" + "22" * 32,
    "policyHash": "0x" + "33" * 32, "txHash": "0x" + "44" * 32,
}
# The largest uint256: `push_amount` draws it as 78 digits and 25 separators, which
# fits a review field and does not fit the home screen's "Key is for" line.
HUGE_CHAIN_ID = 2**256 - 1

failures = []


def check(name, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'}  {name}{'' if ok else ': ' + detail}")
    if not ok:
        failures.append(name)


def cast(*args):
    exe = os.path.expanduser("~/.foundry/bin/cast")
    exe = exe if os.path.exists(exe) else "cast"
    out = subprocess.run([exe, *args], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(" ".join(args) + ": " + (out.stderr.strip() or "cast failed"))
    return out.stdout.strip()


# ── what the app says about itself ───────────────────────────────────────────


def app_consts():
    """`MAX_UTC_SECS`, `TOO_LONG` and `NOT_A_DATE`, read out of `fmt.rs`.

    Read rather than copied: a fix that moves the boundary or reworks the wording
    moves this suite with it, and the boundary is pinned independently below against
    Python's own calendar.
    """
    src = open(FMT_RS).read()

    def const(pattern, name):
        m = re.search(pattern, src)
        if not m:
            sys.exit(f"{FMT_RS} no longer defines {name}")
        return m.group(1)

    return {
        "max": int(const(r"pub const MAX_UTC_SECS: u64 = ([0-9_]+);", "MAX_UTC_SECS").replace("_", "")),
        "too_long": const(r'pub const TOO_LONG: &str = "([^"]*)";', "TOO_LONG"),
        "not_a_date": const(r'pub const NOT_A_DATE: &str = "([^"]*)";', "NOT_A_DATE"),
    }


APP = app_consts()

# ── the calendar, independently ──────────────────────────────────────────────

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def utc_oracle(secs):
    """What the screen must read, from Python's calendar rather than the app's."""
    d = EPOCH + datetime.timedelta(seconds=secs)
    return f"{d.day} {MONTHS[d.month - 1]} {d.year} {d.hour:02d}:{d.minute:02d} UTC"


def days_from_civil(y, m, d):
    """Hinnant's `days_from_civil` — the inverse of the arithmetic the app runs."""
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146_097 + doe - 719_468


def wrapped_twin(secs, eras=1):
    """The `uint64` the old `year as u32` drew exactly like `secs`.

    Same day, same month, same time of day, year 2^32 higher: the cast threw away
    precisely that difference.
    """
    d = EPOCH + datetime.timedelta(seconds=secs)
    return days_from_civil(d.year + eras * 2**32, d.month, d.day) * 86_400 + secs % 86_400


# The pair the review demonstrated on the device, and the sanity check that this
# file's arithmetic produces it.
HONEST_UNTIL = 1790769600
FOREVER_UNTIL = 135536078592187200

# Dates a holder might actually be asked to approve, plus the calendar's awkward
# corners: a leap day, the 1900-is-not-a-leap-year and 2000-is rules, midnight, and
# the last second before the boundary.
FIXED_DATES = [
    0, 1, 86_399, 86_400,
    68_169_600,             # 29 Feb 1972 — a leap year
    951_782_400,            # 29 Feb 2000 — the century that is a leap year
    4_107_542_400,          # 1 Mar 2100  — the century that is not
    HONEST_UNTIL,
    1790000000, 1790086400,  # the pre-approval's own window
    2**31,                  # past the signed-32-bit second
    2**32,                  # past the unsigned-32-bit second
    APP["max"] - 1, APP["max"],
]
REFUSED = [APP["max"] + 1, FOREVER_UNTIL, 2**63, 2**64 - 1]


# ── the host harness: fmt.rs compiled on its own ─────────────────────────────

HARNESS = r'''
#![allow(dead_code)]
#[path = "fmt.rs"]
mod fmt;

use std::io::{self, BufRead, Write};

fn report<const N: usize>(b: &fmt::Buf<N>) -> String {
    format!("{}\t{}", if b.overflowed() { 1 } else { 0 }, b.as_str())
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let mut it = line.split_whitespace();
        let cmd = it.next().unwrap_or("");
        let arg = || -> u64 { it.clone().next().unwrap().parse().unwrap() };
        let text = match cmd {
            // A timestamp into a buffer wide enough for any date.
            "utc" => {
                let mut b = fmt::Buf::<128>::new();
                b.push_utc(arg());
                report(&b)
            }
            // A date into a buffer too small for one: it must not be drawn in part.
            "utc8" => {
                let mut b = fmt::Buf::<8>::new();
                b.push_utc(arg());
                report(&b)
            }
            // n characters into a 16-byte buffer.
            "fill" => {
                let n = arg() as usize;
                let mut b = fmt::Buf::<16>::new();
                for _ in 0..n {
                    b.push_str("x");
                }
                report(&b)
            }
            // A refused timestamp, then the next field of the same review.
            "sticky_utc" => {
                let mut b = fmt::Buf::<128>::new();
                b.push_utc(arg());
                b.clear().push_str("0x1234");
                report(&b)
            }
            // An overflowed field, then the next field of the same review.
            "sticky_fill" => {
                let n = arg() as usize;
                let mut b = fmt::Buf::<16>::new();
                for _ in 0..n {
                    b.push_str("x");
                }
                b.clear().push_str("0x1234");
                report(&b)
            }
            "renderable" => format!("0\t{}", fmt::utc_renderable(arg())),
            "max" => format!("0\t{}", fmt::MAX_UTC_SECS),
            _ => "0\t?".to_string(),
        };
        writeln!(out, "{}", text).unwrap();
    }
}
'''

# The inverse of each fix, as a patch on a copy of fmt.rs. Every `old` must still be
# present in the file, so a rewrite of fmt.rs that leaves these stale says so loudly
# instead of quietly mutating nothing.
MUTATIONS = {
    "wrap-year": [
        ("""        if !utc_renderable(secs) {
            self.tainted = true;
            return self.push_str(NOT_A_DATE);
        }
""", ""),
        ("""        if year < 1970 || year > 9999 {
            self.tainted = true;
            return self.push_str(NOT_A_DATE);
        }
""", ""),
    ],
    "show-prefix": [
        ("""        if self.full {
            return TOO_LONG;
        }
""", ""),
    ],
    "forget-taint": [
        ("""        self.len = 0;
        self.full = false;
        self
""", """        self.len = 0;
        self.full = false;
        self.tainted = false;
        self
"""),
    ],
}


def run_harness(cases, mutate=None):
    """Compile `fmt.rs` with a tiny driver and run every case through it.

    In the same container the app is built in, so the compiler is the app's own; the
    module is pure `core`, so it needs nothing from the device SDK.
    """
    with tempfile.TemporaryDirectory() as work:
        src = open(FMT_RS).read()
        for old, new in MUTATIONS.get(mutate, []):
            if old not in src:
                sys.exit(f"mutation {mutate!r} no longer applies to {FMT_RS} — update MUTATIONS")
            src = src.replace(old, new, 1)
        open(os.path.join(work, "fmt.rs"), "w").write(src)
        open(os.path.join(work, "harness.rs"), "w").write(HARNESS)
        open(os.path.join(work, "cases.txt"), "w").write("\n".join(cases) + "\n")
        out = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work}:/w", "-w", "/w", BUILDER_IMAGE, "bash", "-lc",
             "export PATH=/opt/.cargo/bin:$PATH && "
             "rustc -O --edition 2021 harness.rs -o /tmp/h && /tmp/h < cases.txt"],
            capture_output=True, text=True, timeout=600)
        if out.returncode != 0:
            sys.exit("fmt.rs did not compile:\n" + out.stdout + out.stderr)
        lines = [l for l in out.stdout.splitlines() if "\t" in l]
        if len(lines) != len(cases):
            sys.exit(f"harness answered {len(lines)} of {len(cases)} cases:\n{out.stdout}")
        return [(l.split("\t", 1)[0] == "1", l.split("\t", 1)[1]) for l in lines]


def host_checks(mutate=None):
    check("the review's own pair is the wrapped twin this file computes",
          wrapped_twin(HONEST_UNTIL) == FOREVER_UNTIL,
          f"{wrapped_twin(HONEST_UNTIL)} vs {FOREVER_UNTIL}")

    last = datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)
    check("MAX_UTC_SECS is the last second a four-digit year has",
          APP["max"] == int(last.timestamp()), f"{APP['max']} vs {int(last.timestamp())}")

    rnd = random.Random(20260930)
    dates = FIXED_DATES + [rnd.randrange(0, APP["max"] + 1) for _ in range(200)]
    twins = [wrapped_twin(d) for d in dates]
    cases = (["max"]
             + [f"utc {d}" for d in dates]
             + [f"utc {t}" for t in twins]
             + [f"utc {r}" for r in REFUSED]
             + [f"renderable {r}" for r in [APP["max"], APP["max"] + 1, FOREVER_UNTIL]]
             + [f"utc8 {HONEST_UNTIL}", "fill 15", "fill 16", "fill 17", "fill 200",
                f"sticky_utc {FOREVER_UNTIL}", f"sticky_utc {HONEST_UNTIL}",
                "sticky_fill 17", "sticky_fill 16"])
    r = run_harness(cases, mutate)
    i = 0

    def take():
        nonlocal i
        i += 1
        return r[i - 1]

    check("the app's MAX_UTC_SECS is the one the compiled module uses",
          take()[1] == str(APP["max"]), str(r[0]))

    # Every loop below consumes its whole slice of the harness's answers before it
    # reports — a `break` would leave the rest of the stream misaligned and turn one
    # real failure into a page of nonsense ones.
    bad = []
    for d in dates:
        tainted, text = take()
        if tainted or text != utc_oracle(d):
            bad.append(f"{d} drew {text!r}, Python says {utc_oracle(d)!r}, tainted={tainted}")
    check(f"all {len(dates)} plausible timestamps draw what Python's calendar says, untainted",
          not bad, f"{len(bad)} wrong, first: {bad[0] if bad else ''}")

    bad = []
    for d, t in zip(dates, twins):
        tainted, text = take()
        year = (EPOCH + datetime.timedelta(seconds=d)).year
        if text != APP["not_a_date"] or not tainted or text == utc_oracle(d):
            bad.append(f"validUntil {t} (year {year} + 2^32) drew {text!r}, tainted={tainted}")
    check(f"and each one's wrapped twin is refused, not drawn as its own date ({len(twins)} pairs)",
          not bad, f"{len(bad)} drawn anyway, first: {bad[0] if bad else ''}")

    bad = []
    for s in REFUSED:
        tainted, text = take()
        if text != APP["not_a_date"] or not tainted:
            bad.append(f"{s} drew {text!r}, tainted={tainted}")
    check("the boundary, the review's payload, 2^63 and u64::MAX are all refused",
          not bad, "; ".join(bad))

    ok = [take()[1] for _ in range(3)]
    check("utc_renderable is true at MAX_UTC_SECS and false one second later",
          ok == ["true", "false", "false"], str(ok))

    tainted, text = take()
    check("a real date that does not fit its buffer reads TOO_LONG, not the part that fit",
          text == APP["too_long"] and tainted, f"{text!r} tainted={tainted}")

    for n, want, want_tainted in ((15, "x" * 15, False), (16, "x" * 16, False),
                                  (17, APP["too_long"], True), (200, APP["too_long"], True)):
        tainted, text = take()
        check(f"{n} characters into a 16-byte buffer read {'the value' if not want_tainted else 'TOO_LONG'}",
              text == want and tainted == want_tainted, f"{text!r} tainted={tainted}")

    tainted, text = take()
    check("a refused date taints the buffer for the rest of the review, across clear()",
          tainted and text == "0x1234", f"{text!r} tainted={tainted}")
    tainted, text = take()
    check("and a date that drew fine leaves the buffer clean",
          not tainted and text == "0x1234", f"{text!r} tainted={tainted}")
    tainted, text = take()
    check("an overflowed field taints it the same way, across clear()",
          tainted and text == "0x1234", f"{text!r} tainted={tainted}")
    tainted, text = take()
    check("and a field that fit leaves it clean",
          not tainted and text == "0x1234", f"{text!r} tainted={tainted}")


# ── the device ───────────────────────────────────────────────────────────────


class Emulator:
    """The built app in Speculos, on a container and ports of this file's own.

    Several suites run at once here, so nothing is shared: not the ports, not the
    container name. Two devices are needed because the key slot's contract binding is
    permanent once a signature is approved.
    """

    def __init__(self):
        self.container = None

    def start(self):
        if not os.path.exists(ELF):
            sys.exit(f"no app at {ELF} — run ledger-app/build.sh first, or set FMT_UTC_ELF")
        self.stop()
        # Containers left behind by an interrupted run hold the ports, and the next
        # run would die on a bare "exit status 125".
        stale = subprocess.run(["docker", "ps", "-aq", "--filter", "name=fg-fmt-utc-"],
                               capture_output=True, text=True).stdout.split()
        if stale:
            subprocess.run(["docker", "rm", "-f", *stale], capture_output=True)
        self.container = f"fg-fmt-utc-{os.getpid()}-{int(time.time())}"
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", self.container,
             "-v", os.path.dirname(os.path.abspath(ELF)) + ":/app",
             "-p", f"{API_PORT}:5000", "-p", f"{APDU_PORT}:9999", SPECULOS_IMAGE,
             "--model", "nanosp", "--display", "headless", "--api-port", "5000",
             "--apdu-port", "9999", "--seed", SEED, "/app/" + os.path.basename(ELF)],
            check=True, capture_output=True)
        os.environ["SPECULOS_APDU_URL"] = f"tcp://127.0.0.1:{APDU_PORT}"
        os.environ["SPECULOS_API_URL"] = f"http://127.0.0.1:{API_PORT}"
        tr = transport("speculos")
        for _ in range(60):
            try:
                next_leaf(tr)
                return tr
            except Exception:  # noqa: BLE001 (the emulator is simply not up yet)
                time.sleep(1)
        sys.exit("the app never answered in Speculos")

    def stop(self):
        if self.container:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)
            self.container = None
            os.environ.pop("SPECULOS_APDU_URL", None)
            os.environ.pop("SPECULOS_API_URL", None)
            time.sleep(1)  # let the ports come free before the next container


def send(tr, ins, p1=P1_FIRST, data=b"", timeout=30):
    """One APDU, status word included — this suite asserts on the status word, so it
    does not go through `Device`, which turns it into prose."""
    return tr.exchange(bytes([CLA, ins, p1, KEY_SLOT, len(data)]) + data, timeout)


def next_leaf(tr):
    out, sw = send(tr, INS_GET_LEAF_INDEX)
    if sw != SW_OK:
        raise RuntimeError(f"GET_LEAF_INDEX returned 0x{sw:04x}")
    return int.from_bytes(out, "big")


HOME_PAGES = ("is ready", "Leaves used", "Key is for", "Version", "Quit")

# Every title a page of this app can carry. A Nano review page is read back as its
# title and the first 17 characters of the value glued into one string
# (`" Valid until30 Sep 2026 12:00"`) with the rest in 17-character lines; a home page
# draws its title as a line of its own. Matched longest-first, so `Valid to` cannot
# swallow `Valid until`.
TITLES = sorted((
    "Leaf", "Token", "Amount", "Recipient", "Valid until", "Valid from", "Valid to",
    "Wallet", "Network", "Safe guard", "Safe", "Guard", "Policy", "Binding", "Target",
    "Value", "Data hash", "Administrator", "Key is for", "Leaves used", "Version",
    "Quit", "Approve", "Reject", "Done",
), key=len, reverse=True)


def api(path, method="GET", body=None):
    url = os.environ["SPECULOS_API_URL"].rstrip("/") + path
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read()
    return json.loads(raw) if raw else {}


def clear_events():
    api("/events", "DELETE")


def drawn():
    """Every string the device has drawn since the last `clear_events`.

    The event log, not the current screen: a value wider than the Nano's line is
    wrapped over several lines, and only the log holds all of them.
    """
    return [e["text"] for e in api("/events").get("events", []) if e.get("text")]


def screens():
    """The event log split into `{title: value}`. The pieces of a wrapped value are
    joined with a space, so a check looks for a value's tokens, not one string."""
    out, cur = {}, None
    for t in drawn():
        hit, rest = None, ""
        for name in TITLES:
            if t == name:
                hit = name
                break
            if t.startswith(" " + name):
                hit, rest = name, t[len(name) + 1:]
                break
        if hit:
            cur = hit
            out.setdefault(cur, []).append(rest)
        elif cur:
            out[cur].append(t)
    return {k: " ".join(v).strip() for k, v in out.items()}


def review(tr, decision, dwell=0.4):
    """Walk the review to its decision page and press Approve or Reject.

    In a thread, because the device answers the last chunk only once the human has
    decided. Every page is dwelt on, so all of its lines reach the event log before
    the next press.

    Returns the thread and a `stop` event. A payload that `review_and_digest` refuses
    before any screen — which is now most of what this file sends — never draws a
    review for the walker to find, so the caller must be able to call it off. Without
    that it waits out its whole deadline, outlives the emulator it is polling, and
    prints a `Connection refused` traceback that reads like a device crash.
    """
    stop = threading.Event()

    def home(text):
        return not text or any(p in text for p in HOME_PAGES)

    def run():
        deadline = time.time() + 180
        while time.time() < deadline and not stop.is_set() and home(" ".join(tr.screen())):
            time.sleep(0.1)
        while time.time() < deadline and not stop.is_set():
            text = " ".join(tr.screen())
            if home(text):
                return
            time.sleep(dwell)
            if decision == "approve" and "Approve" in text:
                tr.press("both")
                return
            if decision == "reject" and "Reject" in text:
                tr.press("both")
                return
            tr.press("right")
            time.sleep(0.05)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, stop


def stream(tr, payload, decision, chunk=CHUNK):
    """Stream a payload and decide, exactly as a host would.

    Returns `(data, sw, {title: value})` — what the device answered, and every page it
    drew while asking.
    """
    clear_events()
    walker, stop = review(tr, decision)
    pieces = [payload[i:i + chunk] for i in range(0, len(payload), chunk)] or [b""]
    out, sw = b"", SW_OK
    for i, piece in enumerate(pieces):
        last = i == len(pieces) - 1
        p1 = P1_LAST if last else (P1_FIRST if i == 0 else P1_MORE)
        out, sw = send(tr, INS_SIGN_PREAPPROVAL, p1, piece, 240 if last else 30)
        if sw != SW_OK:
            break
    # The device has answered, so there is nothing left for the walker to press —
    # whether it decided, or the payload was refused before a screen was ever drawn.
    stop.set()
    walker.join(timeout=30)
    return out, sw, screens()


def encode_transfer(wallet, f, chain_id):
    """chainId(32) ‖ wallet(20) ‖ token(20) ‖ to(20) ‖ amount(32) ‖ validUntil(8).

    The leaf index is absent on purpose: it is the device's counter, not the host's.
    """
    def addr(a):
        return bytes.fromhex(a[2:].rjust(40, "0"))

    return b"".join([
        int(chain_id).to_bytes(32, "big"), addr(wallet), addr(f["token"]), addr(f["to"]),
        int(f["amount"]).to_bytes(32, "big"), int(f["validUntil"]).to_bytes(8, "big"),
    ])


def transfer_digest(wallet, f, leaf, chain_id=CHAIN_ID):
    """The digest the FermionWallet contract computes, via `cast` — an independent
    path from the device's own keccak and from the Rust that produced it."""
    domain = cast("keccak", cast(
        "abi-encode", "f(bytes32,bytes32,bytes32,uint256,address)",
        cast("keccak", DOMAIN_TYPE), cast("keccak", "FermionWallet"), cast("keccak", "1"),
        str(chain_id), wallet))
    struct = cast("keccak", cast(
        "abi-encode", "f(bytes32,address,address,address,uint256,uint32,uint64)",
        cast("keccak", TRANSFER_TYPE), wallet, f["token"], f["to"], f["amount"],
        str(leaf), str(f["validUntil"])))
    return cast("keccak", "0x1901" + domain[2:] + struct[2:])


def as_read(text):
    """Text as Speculos' headless reader gives it back.

    It recovers the strings from the rendered glyphs, and on the Nano S Plus font it
    loses a capital S and reads a capital I as a lowercase l: `Send tokens` comes back
    `end tokens`, `30 Sep 2026` as `30 ep 2026`, `FIELD` as `FlELD`. Both sides of
    every comparison below go through this, so a check tests what the device drew and
    not the emulator's eyesight.
    """
    return re.sub(r"\s+", " ", text.upper().replace("S", "").replace("I", "L")).strip()


def tight(text):
    """`as_read`, with every space gone as well: the Nano wraps a value every 17
    characters and the break lands mid-word, so `NOT A DATE - REJECT` comes back as
    `NOT A DATE - REJE` + `CT`. Nothing this suite compares depends on spacing."""
    return re.sub(r"\s+", "", as_read(text))


def reads(haystack, needle):
    """Whether the device drew `needle` somewhere on the page."""
    return tight(needle) in tight(haystack)


def looks_like_a_date(text):
    """Whether a holder could read this page as a date. A month name with a run of
    digits after it is enough — that is all the old screen ever gave them."""
    t = tight(text)
    months = "|".join(tight(m) for m in MONTHS)
    return bool(re.search(r"(" + months + r")[0-9]", t)) or \
        bool(re.search(r"[0-9]{4}[0-9:]*UTC", t))


def device_checks():
    """D1-D3 on one device, D4 on another: an approved signature binds the slot for
    good, and D4 needs a chain id the first three did not bind."""
    twin = wrapped_twin(PRE_APPROVAL["validTo"])
    emu = Emulator()
    try:
        tr = emu.start()

        # ── D1 a Safe pre-approval whose validTo is a wrapped twin ────────────
        start = next_leaf(tr)
        fields = dict(PRE_APPROVAL, validTo=twin)
        out, sw, seen = stream(tr, encode_payload(fields, CHAIN_ID, GUARD), "reject")
        check("D1a: the Guard review is never drawn — no page names a date to misread",
              not seen and not looks_like_a_date(" ".join(seen.values())),
              f"pages drawn: {sorted(seen)!r}")
        check("D1b: the holder is not asked at all: no Valid-to and no Valid-from page",
              "Valid to" not in seen and "Valid from" not in seen, f"{sorted(seen)!r}")
        check("D1c: it is refused as a bad field, not as a human's rejection",
              sw == SW_BAD_FIELDS, f"0x{sw:04x}")
        check("D1d: and costs no one-time leaf", next_leaf(tr) == start, f"leaf {next_leaf(tr)}")

        # ── D2 the normal path, unchanged ─────────────────────────────────────
        out, sw, seen = stream(tr, encode_transfer(WALLET, TRANSFER, CHAIN_ID), "approve")
        check("D2a: a transfer with a plausible validUntil is still signed", sw == SW_OK,
              f"0x{sw:04x}")
        leaf = int.from_bytes(out[:4], "big")
        digest = "0x" + out[4:36].hex()
        until = seen.get("Valid until", "")
        want_until = utc_oracle(TRANSFER["validUntil"])
        # Token by token rather than as one string: the Nano wraps a value at 17
        # characters and the log holds it in pieces.
        check("D2b: and its Valid-until page reads the date Python's calendar gives",
              all(reads(until, t) for t in want_until.split())
              and not reads(until, APP["not_a_date"]),
              f"{until!r} wanted {want_until!r}")
        want = transfer_digest(WALLET, TRANSFER, leaf)
        check("D2c: over the fields that were sent — the digest still agrees with cast",
              digest.lower() == want.lower(), f"device {digest} vs cast {want}")
        check("D2d: and it consumed exactly one leaf",
              leaf == start and next_leaf(tr) == leaf + 1, f"leaf {leaf}, start {start}")

        # ── D3 the same transfer, with the wrapped twin ───────────────────────
        start = next_leaf(tr)
        out, sw, seen = stream(
            tr, encode_transfer(WALLET, dict(TRANSFER, validUntil=FOREVER_UNTIL), CHAIN_ID),
            "reject")
        twin_until = seen.get("Valid until", "")
        check("D3a: the transfer review draws no Valid-until page for validUntil "
              "135536078592187200 — it draws no page at all",
              not seen and not looks_like_a_date(" ".join(seen.values())),
              f"pages drawn: {sorted(seen)!r}")
        check("D3b: so nothing on screen can render as the 2026 window it wrapped onto",
              tight(twin_until) != tight(until), f"{twin_until!r} vs {until!r}")
        check("D3c: it is refused as a bad field before any screen, and costs no leaf",
              sw == SW_BAD_FIELDS and next_leaf(tr) == start,
              f"0x{sw:04x}, leaf {next_leaf(tr)}, expected {start}")

        # ── D5 the boundary itself, on the device ─────────────────────────────
        #
        # The last second that still draws, and the first one that does not. The first
        # is reviewed and rejected by hand; the second never reaches a screen, because
        # the gate refuses it. Neither costs a leaf.
        edge = {}
        for label, secs in (("last", APP["max"]), ("first refused", APP["max"] + 1)):
            _, sw, seen = stream(
                tr, encode_transfer(WALLET, dict(TRANSFER, validUntil=secs), CHAIN_ID), "reject")
            edge[label] = (seen.get("Valid until", ""), sw, sorted(seen))
        page, sw, pages = edge["last"]
        check(f"D5a: validUntil {APP['max']} still draws its date, {utc_oracle(APP['max'])}",
              all(reads(page, t) for t in utc_oracle(APP["max"]).split())
              and not reads(page, APP["not_a_date"]), f"{page!r}")
        page, sw, pages = edge["first refused"]
        check(f"D5b: and one second later, {APP['max'] + 1}, draws no page at all",
              not pages and not looks_like_a_date(page), f"pages drawn: {pages!r}")
        check("D5c: the renderable one is a human's rejection, the other a bad field, "
              "and neither cost a leaf",
              edge["last"][1] == SW_DENIED and edge["first refused"][1] == SW_BAD_FIELDS
              and next_leaf(tr) == start,
              f"0x{edge['last'][1]:04x} / 0x{edge['first refused'][1]:04x}, "
              f"leaf {next_leaf(tr)}, expected {start}")
    finally:
        emu.stop()

    # ── D4 the binding, drawn whole, on a device with a clean binding ─────────
    #
    # `chainId = 2^256 - 1` is the widest value this app can be asked to draw: 78
    # digits and 25 separators, 103 characters. The review's own Network field holds it
    # because `MultiFieldReview` paginates a value over as many pages as it needs. The
    # home screen's `Page` does not paginate at all — it draws three lines of
    # `MAX_CHAR_PER_LINE` and silently drops the rest — so `Safe guard ‹address› on
    # chain ‹id›` used to lose the chain id at 51 characters even on chain 31337, and
    # would have lost most of the address here. The binding therefore lives in a review
    # of its own, opened from the home page, and the home page itself carries nothing
    # but a fixed string.
    try:
        tr = emu.start()
        out, sw, _ = stream(tr, encode_transfer(WALLET, TRANSFER, HUGE_CHAIN_ID), "approve")
        check("D4a: a transfer on chain 2^256-1 is signed — the review's own fields fit",
              sw == SW_OK, f"0x{sw:04x}")

        # Any APDU rebuilds the home menu at page 0. Right twice to "Key is for", both
        # buttons to open the binding review, then right through its pages: the value of
        # a 103-character chain id is spread over several of them, and only the event
        # log holds all the lines.
        clear_events()
        next_leaf(tr)
        for _ in range(2):
            tr.press("right")
            time.sleep(0.4)
        page = " ".join(tr.screen())
        check("D4b: the home page carries a fixed string, with no value to cut short",
              reads(page, "Key is for") and reads(page, "a FermionWallet")
              and not reads(page, APP["too_long"]), f"{page!r}")

        tr.press("both")
        time.sleep(0.5)
        for _ in range(14):
            tr.press("right")
            time.sleep(0.35)
        seen = screens()
        wallet_page = seen.get("Wallet", "")
        network_page = seen.get("Network", "")
        check("D4c: opening it draws the bound contract in full, EIP-55 and unabbreviated",
              reads(wallet_page, WALLET), f"{wallet_page!r} wanted {WALLET}")
        # A value too wide for one page comes back as `(1/3)…(2/3)…(3/3)…`: the SDK's
        # own page markers, plus `push_amount`'s thousands separators and the line
        # breaks the Nano wraps at. Strip all three and what is left must be the number
        # itself, to the last digit — that is the whole claim.
        digits = re.sub(r"\(\d+/\d+\)|[,\s]", "", network_page)
        check("D4d: and all 78 digits of the chain id, every one of 2^256-1",
              digits == str(HUGE_CHAIN_ID) and not reads(network_page, APP["too_long"]),
              f"{digits!r} wanted {HUGE_CHAIN_ID}")

        # Out of the review and back to a device that still answers.
        tr.press("both")
        time.sleep(0.5)
        check("D4e: and the device is still answering afterwards", next_leaf(tr) == 1,
              f"leaf {next_leaf(tr)}")
    finally:
        emu.stop()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", action="store_true", help="the host checks only")
    ap.add_argument("--device", action="store_true", help="the Speculos checks only")
    ap.add_argument("--mutate", choices=sorted(MUTATIONS), help="plant a fix's inverse")
    args = ap.parse_args()

    if args.mutate:
        print(f"-- fmt.rs mutated: {args.mutate} (a copy; the tree is untouched)\n")
    if not args.device:
        host_checks(args.mutate)
    if not args.host:
        print()
        device_checks()

    if failures:
        print(f"\n{len(failures)} FAILED: " + ", ".join(failures))
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
