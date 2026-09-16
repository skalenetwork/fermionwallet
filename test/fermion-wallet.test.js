import test from 'node:test';
import assert from 'node:assert/strict';

import { ERC20Token, FermionWallet } from '../src/fermion-wallet.js';

test('standard ERC-20 approve flow works', () => {
  const token = new ERC20Token('Fermion', 'FERM');
  const wallet = new FermionWallet('0xOwner');
  token.mint('0xOwner', 1000n);

  const approval = wallet.approve(token, '0xSpender', 250n);

  assert.equal(approval.amount, 250n);
  assert.equal(token.allowance('0xOwner', '0xSpender'), 250n);
});

test('quantum key generation and status are tracked', () => {
  const wallet = new FermionWallet('0xOwner');
  const key = wallet.generateQuantumKeyPair();

  assert.equal(key.status, 'active');
  assert.equal(wallet.getQuantumKeyStatus(key.quantumKeyId).status, 'active');
});

test('pre-approval validates and executes a token transfer', () => {
  const token = new ERC20Token('Fermion', 'FERM');
  const wallet = new FermionWallet('0xOwner');
  const spender = '0xVault';

  token.mint('0xOwner', 1000n);
  const quantumKey = wallet.generateQuantumKeyPair();

  const now = Date.now();
  const preApproval = wallet.createPreApproval({
    token,
    spender,
    amount: 200n,
    validFrom: now - 1000,
    validTo: now + 30000,
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
  const wallet = new FermionWallet('0xOwner');
  token.mint('0xOwner', 1000n);

  const quantumKey = wallet.generateQuantumKeyPair();
  const now = Date.now();

  const preApproval = wallet.createPreApproval({
    token,
    spender: '0xVault',
    amount: 50n,
    validFrom: now - 1000,
    validTo: now + 5000,
    nonce: 'n-2',
    quantumKeyId: quantumKey.quantumKeyId,
    policyHash: 'policy-xyz'
  });

  wallet.revokePreApproval(preApproval.preApprovalId);
  assert.equal(wallet.validatePreApproval(preApproval.preApprovalId).valid, false);

  const expired = wallet.createPreApproval({
    token,
    spender: '0xVault',
    amount: 10n,
    validFrom: now - 5000,
    validTo: now - 1000,
    nonce: 'n-3',
    quantumKeyId: quantumKey.quantumKeyId,
    policyHash: 'policy-expired'
  });
  assert.equal(wallet.validatePreApproval(expired.preApprovalId).valid, false);
});

test('quantum key rotation updates status and preserves new active key', () => {
  const wallet = new FermionWallet('0xOwner');
  const key = wallet.generateQuantumKeyPair();
  const rotated = wallet.rotateQuantumKey(key.quantumKeyId);

  assert.equal(wallet.getQuantumKeyStatus(key.quantumKeyId).status, 'rotated');
  assert.equal(wallet.getQuantumKeyStatus(rotated.newQuantumKeyId).status, 'active');
});
