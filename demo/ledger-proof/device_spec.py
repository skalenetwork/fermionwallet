#!/usr/bin/env python3
"""Executable specification of the signing device's flow (hybrid ECDSA + ML-DSA-65).

The device rules of the ML-DSA redesign written as a state machine, independently of
any implementation. prove_device.py model-checks this machine exhaustively.

ML-DSA-65 keeps no per-signature state, so there is no leaf counter, no exhaustion
and no commit-before-release ordering to model: what is left to get right is *what*
the device agrees to sign. The machine covers one signing session:

    idle --start(payload)--> screen 0 --next/prev--> ... --approve--> idle (signed)
             \\--refused--> idle                          \\--reject/timeout--> idle

The host chooses every payload, including ones the device must refuse, and also sends
a hash of its own. The device never signs that hash: it signs the digest it derives
from the fields it displayed (FWL-014).

Nothing here talks to a host, a file or a clock.
"""
from dataclasses import dataclass, replace
from itertools import product

# The screens of each payload kind, in order. Every flow ends on the decision screen,
# and Approve is offered only there, after every screen before it has been shown.
FLOWS = {
    # FermionWallet `Transfer`, and the Guard's transfer approval.
    "transfer": ("header", "token", "amount", "recipient", "validity", "context", "policy", "decision"),
    # A Safe transaction: FermionWallet signing as a Safe owner (ERC-1271), or a Guard approval.
    "safetx": ("header", "safe", "to", "value", "call", "nonce", "context", "decision"),
    # A plain-text message (address-ownership proofs, Sign-In with Ethereum), shown in full.
    "message": ("header", "text", "context", "decision"),
    # An arbitrary contract call, displayed through its ERC-7730 descriptor.
    "call": ("header", "contract", "function", "arguments", "value", "context", "decision"),
    # An ERC-20 approval: the spender and the amount are shown.
    "approve": ("header", "token", "spender", "amount", "context", "decision"),
    # Enabling a Safe module, the most powerful change a Safe can make: its own warning.
    "enable_module": ("header", "module warning", "module", "context", "decision"),
}

MODULE_WARNING = "module warning"


@dataclass(frozen=True)
class Payload:
    """What the host asks the device to sign. Every field is the host's choice.

    `displayable`    — a `call` the device can render (it has an ERC-7730 descriptor).
    `refund_free`    — a `safetx` whose gasPrice, gasToken and refundReceiver are all zero.
    `call_operation` — a `safetx` whose operation is Call, not DelegateCall.
    `unlimited`      — an `approve` for the maximum amount.
    A flag that does not apply to the payload's kind means nothing.
    """

    kind: str
    well_formed: bool = True
    displayable: bool = True
    refund_free: bool = True
    call_operation: bool = True
    unlimited: bool = False


PAYLOADS = tuple(
    Payload(kind, *flags) for kind in FLOWS for flags in product((True, False), repeat=5)
)

# The hash a host sends along with the fields. A correct device ignores it.
HOST_HASH = "host-supplied hash"


def digest(p: Payload):
    """The EIP-712 digest the device derives from the fields it displays. Opaque here:
    all that matters is that it is a function of the payload and nothing else."""
    return ("eip712", p)


def refusal(p: Payload):
    """Why the device refuses a payload before showing any screen, or None.

    The SafeTx rule is the one the ML-DSA redesign must not lose: a host that shows an
    innocent `to`/`value`/`data` but sets a gas refund paid to itself, or a
    DelegateCall, is asking for a signature that pays or hands the Safe to the host.
    A FermionGuard Safe also refuses these on-chain; a Safe with a FermionWallet owner
    has only the device. (`NonZeroClassFields` is the same rule for Guard approvals.)
    """
    if not p.well_formed:
        return "Payload rejected"
    if p.kind == "call" and not p.displayable:
        return "Cannot display this call"
    if p.kind == "safetx" and not p.refund_free:
        return "Gas refunds are refused"
    if p.kind == "safetx" and not p.call_operation:
        return "Delegatecall is refused"
    if p.kind == "approve" and p.unlimited:
        return "Unlimited approvals are refused"
    return None


@dataclass(frozen=True)
class Device:
    payload: Payload | None = None  # what is on display; None = no session in flight
    index: int = -1                 # screen on display
    seen: int = -1                  # highest screen reached with `next`
    host_hash: str | None = None    # what the host sent alongside; never signed
    out: tuple | None = None        # ghost: the digest released by the last step, if any

    @property
    def active(self) -> bool:
        return self.payload is not None

    @property
    def decision(self) -> int:
        return len(FLOWS[self.payload.kind]) - 1

    @property
    def can_approve(self) -> bool:
        """Approve only on the decision screen, after every screen was traversed."""
        return self.active and self.index == self.decision and self.seen == self.decision


IDLE = Device()


def start(d: Device, p: Payload, host_hash: str = HOST_HASH) -> tuple[Device, str]:
    """A signing request. Refused while another session is in flight, and refused
    outright, before any screen, when `refusal` says so."""
    if d.active:
        return replace(d, out=None), "Session already active"
    reason = refusal(p)
    if reason:
        return replace(d, out=None), reason
    return Device(payload=p, index=0, seen=0, host_hash=host_hash), "ok"


def press(d: Device, button: str) -> tuple[Device, str]:
    if not d.active:
        return replace(d, out=None), "No signing session on the device"
    if button == "next":
        i = min(d.index + 1, d.decision)
        return replace(d, index=i, seen=max(d.seen, i), out=None), "ok"
    if button == "prev":
        return replace(d, index=max(d.index - 1, 0), out=None), "ok"
    if button == "reject":
        return IDLE, "rejected"
    if button == "approve":
        if not d.can_approve:
            return replace(d, out=None), "Review every screen before approving"
        # Both halves are produced over the digest derived from the displayed fields.
        return replace(IDLE, out=digest(d.payload)), "approved"
    return replace(d, out=None), "unknown button"


def timeout(d: Device) -> tuple[Device, str]:
    """Idle on the decision screen = reject: nothing is signed."""
    if not d.active:
        return replace(d, out=None), "No signing session on the device"
    return IDLE, "timeout"


EVENTS = ("next", "prev", "approve", "reject")
