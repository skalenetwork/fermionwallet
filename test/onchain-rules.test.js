// The prototype must never accept what the on-chain PreApprovalEngine / Guard would
// reject for the same inputs (contracts/src/PreApprovalEngine.sol). Each test names
// the on-chain rule it mirrors.
import test from 'node:test';
import assert from 'node:assert/strict';

import { ERC20Token, FermionWallet, MIN_WINDOW_MS } from '../src/fermion-wallet.js';

const T0 = 1_800_000_000_000; // fixed clock, ms

function setup() {
  const clock = { t: T0 };
  const token = new ERC20Token('Fermion', 'FERM');
  const wallet = new FermionWallet('0xOwner', { now: () => clock.t });
  token.mint('0xOwner', 1000n);
  const key = wallet.generateQuantumKeyPair();
  const base = {
    token,
    recipient: '0xVault',
    amount: 100n,
    validFrom: T0,
    validTo: T0 + MIN_WINDOW_MS,
    nonce: 'n-1',
    quantumKeyId: key.quantumKeyId,
    policyHash: 'policy-1'
  };
  return { clock, token, wallet, key, base };
}

test('MIN_WINDOW matches the contract (15 minutes)', () => {
  assert.equal(MIN_WINDOW_MS, 15 * 60 * 1000);
});

test('transfer goes only to the signed recipient (_fieldsMatch: recipient)', () => {
  const { token, wallet, base } = setup();
  const pa = wallet.createPreApproval(base);
  assert.throws(() => wallet.executePreApprovedTransfer(pa.preApprovalId, '0xAttacker', 100n), /recipient/i);
  assert.equal(token.balanceOf('0xAttacker'), 0n);
  const ok = wallet.executePreApprovedTransfer(pa.preApprovalId, '0xVault', 100n);
  assert.equal(ok.status, 'success');
});

test('amount must match exactly, not merely be <= (_fieldsMatch: amount)', () => {
  const { token, wallet, base } = setup();
  const pa = wallet.createPreApproval(base);
  assert.throws(() => wallet.executePreApprovedTransfer(pa.preApprovalId, '0xVault', 1n), /amount/i);
  assert.equal(token.balanceOf('0xVault'), 0n);
  assert.equal(wallet.validatePreApproval(pa.preApprovalId).valid, true, 'a rejected attempt must not consume it');
});

test('negative amounts are rejected (uint256), and cannot pull funds from the recipient', () => {
  const { token, wallet, base } = setup();
  assert.throws(() => wallet.createPreApproval({ ...base, amount: -100n }), /amount/i);
  const pa = wallet.createPreApproval(base);
  token.mint('0xVault', 500n);
  assert.throws(() => wallet.executePreApprovedTransfer(pa.preApprovalId, '0xVault', -500n));
  assert.equal(token.balanceOf('0xOwner'), 1000n);
  assert.equal(token.balanceOf('0xVault'), 500n);
});

test('ERC20Token model rejects negative mint/transfer/approve/transferFrom', () => {
  const token = new ERC20Token('Fermion', 'FERM');
  token.mint('0xA', 10n);
  token.mint('0xB', 10n);
  assert.throws(() => token.mint('0xA', -1n));
  assert.throws(() => token.transfer('0xA', '0xB', -5n));
  assert.throws(() => token.approve('0xA', '0xB', -5n));
  assert.throws(() => token.transferFrom('0xB', '0xA', '0xB', -5n));
  assert.equal(token.balanceOf('0xA'), 10n);
  assert.equal(token.balanceOf('0xB'), 10n);
});

test('the signature binds the token: swapping the stored token invalidates it', () => {
  const { wallet, base } = setup();
  const other = new ERC20Token('Other', 'OTH');
  other.mint('0xOwner', 1000n);
  const pa = wallet.createPreApproval(base);
  assert.equal(wallet.validatePreApproval(pa.preApprovalId).valid, true);
  wallet.preApprovals.get(pa.preApprovalId).token = other;
  assert.equal(wallet.validatePreApproval(pa.preApprovalId).valid, false);
});

test('the signature binds every field: tampering recipient/amount/window invalidates it', () => {
  for (const [field, value] of [['recipient', '0xAttacker'], ['amount', '999'], ['validTo', T0 + 10 * MIN_WINDOW_MS]]) {
    const { wallet, base } = setup();
    const pa = wallet.createPreApproval(base);
    assert.equal(wallet.validatePreApproval(pa.preApprovalId).valid, true);
    wallet.preApprovals.get(pa.preApprovalId)[field] = value;
    assert.equal(wallet.validatePreApproval(pa.preApprovalId).valid, false, field);
  }
});

test('nonce is unique per wallet (ApprovalExists)', () => {
  const { wallet, base } = setup();
  wallet.createPreApproval(base);
  assert.throws(() => wallet.createPreApproval(base), /nonce/i);
  assert.throws(() => wallet.createPreApproval({ ...base, amount: 5n }), /nonce/i);
});

test('window rules match _create (InvalidWindow)', () => {
  const { wallet, base } = setup();
  let n = 0;
  const make = (validFrom, validTo) => wallet.createPreApproval({ ...base, nonce: `w-${n++}`, validFrom, validTo });
  assert.throws(() => make(T0 + 10, T0), /window/i, 'inverted');
  assert.throws(() => make(T0, T0 + MIN_WINDOW_MS - 1), /window/i, 'shorter than MIN_WINDOW');
  assert.throws(() => make(T0 - 2 * MIN_WINDOW_MS, T0), /window/i, 'validTo <= now');
  assert.ok(make(T0 + 1000, T0 + 1000 + MIN_WINDOW_MS).preApprovalId, 'scheduled future window is fine');
});

test('window bounds are inclusive at execution (validFrom <= now <= validTo)', () => {
  const { clock, wallet, base } = setup();
  const pa = wallet.createPreApproval({ ...base, validFrom: T0 + 1000, validTo: T0 + 1000 + MIN_WINDOW_MS });
  assert.equal(wallet.validatePreApproval(pa.preApprovalId).valid, false);
  clock.t = T0 + 1000;
  assert.equal(wallet.validatePreApproval(pa.preApprovalId).valid, true);
  clock.t = T0 + 1000 + MIN_WINDOW_MS;
  assert.equal(wallet.validatePreApproval(pa.preApprovalId).valid, true);
  clock.t += 1;
  assert.equal(wallet.validatePreApproval(pa.preApprovalId).valid, false);
});

test('a used pre-approval cannot be replayed', () => {
  const { token, wallet, base } = setup();
  const pa = wallet.createPreApproval(base);
  wallet.executePreApprovedTransfer(pa.preApprovalId, '0xVault', 100n);
  assert.throws(() => wallet.executePreApprovedTransfer(pa.preApprovalId, '0xVault', 100n));
  assert.equal(token.balanceOf('0xVault'), 100n);
});

test('one active key per wallet (SafeAlreadyEnrolled): rotate, do not re-generate', () => {
  const { wallet } = setup();
  assert.throws(() => wallet.generateQuantumKeyPair(), /active/i);
});

test('approvals made under a rotated key stay executable; new ones need the new key', () => {
  const { wallet, key, base } = setup();
  const pa = wallet.createPreApproval(base);
  const rotated = wallet.rotateQuantumKey(key.quantumKeyId);
  assert.equal(wallet.validatePreApproval(pa.preApprovalId).valid, true);
  assert.throws(() => wallet.createPreApproval({ ...base, nonce: 'n-2' }));
  assert.ok(wallet.createPreApproval({ ...base, nonce: 'n-2', quantumKeyId: rotated.newQuantumKeyId }).preApprovalId);
});

test('old spender field is refused, not silently accepted', () => {
  const { wallet, base } = setup();
  const { recipient, ...rest } = base;
  assert.throws(() => wallet.createPreApproval({ ...rest, spender: recipient }), /recipient/);
});

test('demo signatures are labelled as HMAC demo, never as post-quantum', () => {
  const { wallet, key, base } = setup();
  const status = wallet.getQuantumKeyStatus(key.quantumKeyId);
  assert.equal(status.algorithm, 'hmac-sha256-demo');
  assert.equal(status.postQuantum, false);
  const pa = wallet.createPreApproval(base);
  wallet.preApprovals.get(pa.preApprovalId).signature = '00'.repeat(32);
  const res = wallet.validatePreApproval(pa.preApprovalId);
  assert.equal(res.valid, false);
  assert.doesNotMatch(res.reason, /quantum/i);
  const out = JSON.stringify({ status, pa: { ...pa, token: undefined }, res });
  assert.doesNotMatch(out, /pqc|post-quantum signature|hybrid/i);
});
