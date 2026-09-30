import test from 'node:test';
import assert from 'node:assert/strict';

import { ERC20Token, FermionGuard, MIN_WINDOW_MS } from '../src/index.js';

test('standard ERC-20 approve flow works', () => {
  const token = new ERC20Token('Fermion', 'FERM');
  const wallet = new FermionGuard('0xOwner');
  token.mint('0xOwner', 1000n);

  const approval = wallet.approve(token, '0xSpender', 250n);

  assert.equal(approval.amount, 250n);
  assert.equal(token.allowance('0xOwner', '0xSpender'), 250n);
});

test('quantum key generation and status are tracked', () => {
  const wallet = new FermionGuard('0xOwner');
  const key = wallet.generateQuantumKeyPair();

  assert.equal(key.status, 'active');
  assert.equal(wallet.getQuantumKeyStatus(key.quantumKeyId).status, 'active');
});

test('pre-approval validates and executes a token transfer', () => {
  const token = new ERC20Token('Fermion', 'FERM');
  const wallet = new FermionGuard('0xOwner');

  token.mint('0xOwner', 1000n);
  const quantumKey = wallet.generateQuantumKeyPair();

  const now = Date.now();
  const preApproval = wallet.createPreApproval({
    token,
    recipient: '0xRecipient',
    amount: 200n,
    validFrom: now - 1000,
    validTo: now + MIN_WINDOW_MS,
    nonce: 'n-1',
    quantumKeyId: quantumKey.quantumKeyId,
    policyHash: 'policy-abc'
  });

  const validation = wallet.validatePreApproval(preApproval.preApprovalId);
  assert.equal(validation.valid, true);

  const result = wallet.executePreApprovedTransfer(preApproval.preApprovalId, '0xRecipient', 200n);
  assert.equal(result.status, 'success');
  assert.equal(token.balanceOf('0xRecipient'), 200n);
  assert.equal(token.balanceOf('0xOwner'), 800n);
});

test('revoked and expired pre-approvals are rejected', () => {
  const token = new ERC20Token('Fermion', 'FERM');
  let now = Date.now();
  const wallet = new FermionGuard('0xOwner', { now: () => now });
  token.mint('0xOwner', 1000n);

  const quantumKey = wallet.generateQuantumKeyPair();

  const preApproval = wallet.createPreApproval({
    token,
    recipient: '0xVault',
    amount: 50n,
    validFrom: now - 1000,
    validTo: now + MIN_WINDOW_MS,
    nonce: 'n-2',
    quantumKeyId: quantumKey.quantumKeyId,
    policyHash: 'policy-xyz'
  });

  wallet.revokePreApproval(preApproval.preApprovalId);
  assert.equal(wallet.validatePreApproval(preApproval.preApprovalId).valid, false);
  assert.throws(() => wallet.revokePreApproval(preApproval.preApprovalId), /not revocable/);
  assert.throws(() => wallet.executePreApprovedTransfer(preApproval.preApprovalId, '0xVault', 50n), /revoked/);

  const expiring = wallet.createPreApproval({
    token,
    recipient: '0xVault',
    amount: 10n,
    validFrom: now,
    validTo: now + MIN_WINDOW_MS,
    nonce: 'n-3',
    quantumKeyId: quantumKey.quantumKeyId,
    policyHash: 'policy-expired'
  });
  now += MIN_WINDOW_MS + 1;
  const result = wallet.validatePreApproval(expiring.preApprovalId);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'Pre-approval expired');
  assert.equal(token.balanceOf('0xVault'), 0n);
});

test('quantum key rotation updates status and preserves new active key', () => {
  const wallet = new FermionGuard('0xOwner');
  const key = wallet.generateQuantumKeyPair();
  const rotated = wallet.rotateQuantumKey(key.quantumKeyId);

  assert.equal(wallet.getQuantumKeyStatus(key.quantumKeyId).status, 'rotated');
  assert.equal(wallet.getQuantumKeyStatus(rotated.newQuantumKeyId).status, 'active');
});
