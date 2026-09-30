#!/usr/bin/env python3
"""Executable specification of the FermionGuard Ledger app's signing flow.

The rules of ledger-xmss-app.md ("Flow 2 — Sign pre-approval", "Device UI
acceptance criteria") and ledger-ui.md written as a state machine, independently
of the simulator that implements them. prove_device.py model-checks this machine
exhaustively and proves demo/ledger_sim.py refines it, state for state.

The machine covers one signing session on one key slot:

    idle --SIGN--> screen 0 --next/prev--> ... --approve--> signed
                                            \--reject/timeout--> aborted

Nothing here talks to a host, a file or a clock; the leaf counter is the only
state that survives a session.
"""
from dataclasses import dataclass, replace

SCREENS = 8  # spec Flow 2: header, token, amount, recipient, validity, context, policy, decision
DECISION = SCREENS - 1


@dataclass(frozen=True)
class Device:
    """Device state. `leaf` is the monotonic counter in secure-element NVM."""

    leaf: int  # next unused leaf index
    height: int  # tree height: 2**height leaves in total
    index: int = -1  # screen on display; -1 = no session in flight
    seen: int = -1  # highest screen reached with `next`
    committed: int = 0  # counter writes that reached NVM (for the ordering invariant)
    released: int = 0  # signature releases (must never precede the matching commit)

    @property
    def active(self) -> bool:
        return self.index >= 0

    @property
    def exhausted(self) -> bool:
        return self.leaf >= (1 << self.height)

    @property
    def can_approve(self) -> bool:
        """The Approve action is offered only on the decision screen, and only once
        every field screen has been traversed (ledger-xmss-app.md acceptance criteria:
        "no signature without full-field traversal")."""
        return self.active and self.index == DECISION and self.seen == DECISION


def start(d: Device, payload_ok: bool) -> tuple[Device, str]:
    """SIGN_PREAPPROVAL. Malformed fields abort before screen 1; a second session is
    refused while one is in flight; an exhausted key refuses to sign at all."""
    if d.active:
        return d, "Session already active"
    if not payload_ok:
        return d, "Payload rejected"
    if d.exhausted:
        return d, "Key exhausted"
    return replace(d, index=0, seen=0), "ok"


def press(d: Device, button: str) -> tuple[Device, str]:
    if not d.active:
        return d, "No signing session on the device"
    if button == "next":
        i = min(d.index + 1, DECISION)
        return replace(d, index=i, seen=max(d.seen, i)), "ok"
    if button == "prev":
        return replace(d, index=max(d.index - 1, 0)), "ok"
    if button == "reject":
        return replace(d, index=-1, seen=-1), "rejected"
    if button == "approve":
        if not d.can_approve:
            return d, "Review every screen before approving"
        # Counter-before-signature: the commit reaches NVM, then both halves are
        # released over the same digest (ledger-xmss-app.md item 2).
        d = replace(d, leaf=d.leaf + 1, committed=d.committed + 1)
        return replace(d, index=-1, seen=-1, released=d.released + 1), "approved"
    return d, "unknown button"


def timeout(d: Device) -> tuple[Device, str]:
    """60 s idle on the decision screen = reject: no signature, no leaf consumed."""
    if not d.active:
        return d, "No signing session on the device"
    return replace(d, index=-1, seen=-1), "timeout"


EVENTS = ("next", "prev", "approve", "reject")
