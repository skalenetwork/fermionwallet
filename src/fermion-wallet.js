import crypto from 'node:crypto';

// This is an early JavaScript MODEL of the approval flow, not the enforcement layer.
// Signatures here are HMAC-SHA256 demo MACs: symmetric (whoever can verify can forge),
// NOT post-quantum and NOT production-grade. The real rules are enforced on-chain by
// contracts/src/PreApprovalEngine.sol with hybrid ECDSA + XMSS signatures; this model
// mirrors its TRANSFER-class matching rules (see readme "Prototype").

export const DEMO_SIGNATURE_ALGORITHM = 'hmac-sha256-demo';
// PreApprovalEngine.MIN_WINDOW is 15 minutes; the prototype's clock is in milliseconds.
export const MIN_WINDOW_MS = 15 * 60 * 1000;

function stableStringify(payload) {
  // Flat payloads of primitives only: a nested object would be silently dropped by
  // JSON.stringify's key allow-list and leave that field unsigned.
  const out = {};
  for (const k of Object.keys(payload).sort()) {
    const v = payload[k];
    if (v !== null && typeof v === 'object') {
      throw new Error(`Cannot sign nested value for "${k}"`);
    }
    out[k] = typeof v === 'bigint' ? v.toString() : v;
  }
  return JSON.stringify(out);
}

function toUint(amount, what = 'amount') {
  let value;
  try {
    value = BigInt(amount);
  } catch {
    throw new Error(`Invalid ${what}: must be a non-negative integer`);
  }
  if (value < 0n) {
    throw new Error(`Invalid ${what}: must be a non-negative integer`);
  }
  return value;
}

export class ERC20Token {
  constructor(name, symbol, address = `0x${crypto.randomBytes(20).toString('hex')}`) {
    this.name = name;
    this.symbol = symbol;
    this.address = address; // identity that pre-approval signatures bind to
    this.balances = new Map();
    this.allowances = new Map();
  }

  mint(owner, amount) {
    const value = toUint(amount);
    const next = (this.balances.get(owner) ?? 0n) + value;
    this.balances.set(owner, next);
    return next;
  }

  balanceOf(owner) {
    return this.balances.get(owner) ?? 0n;
  }

  approve(owner, spender, amount) {
    const value = toUint(amount);
    const key = `${owner}:${spender}`;
    const current = this.allowances.get(key) ?? 0n;
    this.allowances.set(key, value);
    return { owner, spender, amount: value, previousAmount: current };
  }

  allowance(owner, spender) {
    const key = `${owner}:${spender}`;
    return this.allowances.get(key) ?? 0n;
  }

  transfer(owner, to, amount) {
    const value = toUint(amount);
    if (this.balanceOf(owner) < value) {
      throw new Error('Insufficient balance');
    }
    this.balances.set(owner, this.balanceOf(owner) - value);
    this.balances.set(to, this.balanceOf(to) + value);
    return true;
  }

  transferFrom(spender, from, to, amount) {
    const value = toUint(amount);
    const key = `${from}:${spender}`;
    const approved = this.allowances.get(key) ?? 0n;

    if (approved < value) {
      throw new Error('Allowance exceeded');
    }

    if (this.balanceOf(from) < value) {
      throw new Error('Insufficient balance');
    }

    this.allowances.set(key, approved - value);
    this.balances.set(from, this.balanceOf(from) - value);
    this.balances.set(to, this.balanceOf(to) + value);
    return true;
  }
}

export class QuantumKeyManager {
  constructor() {
    this.keys = new Map();
  }

  generateQuantumKeyPair() {
    // On-chain a Safe enrolls once (SafeAlreadyEnrolled) and then rotates.
    for (const k of this.keys.values()) {
      if (k.status === 'active') {
        throw new Error('An active key already exists: rotate it instead of generating another');
      }
    }
    const quantumKeyId = `qk-${crypto.randomUUID()}`;
    const secret = crypto.randomBytes(32).toString('hex');
    const walletPublicKey = `pub-${crypto.randomBytes(16).toString('hex')}`;
    const key = {
      id: quantumKeyId,
      secret,
      publicKey: walletPublicKey,
      algorithm: DEMO_SIGNATURE_ALGORITHM,
      status: 'active',
      createdAt: Date.now(),
      rotatedAt: null,
      useCounter: 0
    };

    this.keys.set(quantumKeyId, key);
    return {
      quantumKeyId,
      publicKey: walletPublicKey,
      algorithm: key.algorithm,
      postQuantum: false,
      status: key.status
    };
  }

  rotateQuantumKey(quantumKeyId) {
    const key = this.keys.get(quantumKeyId);
    if (!key) {
      throw new Error('Unknown quantum key');
    }

    key.status = 'rotated';
    key.rotatedAt = Date.now();

    const newId = `qk-${crypto.randomUUID()}`;
    const newSecret = crypto.randomBytes(32).toString('hex');
    const newPublicKey = `pub-${crypto.randomBytes(16).toString('hex')}`;

    const replacement = {
      id: newId,
      secret: newSecret,
      publicKey: newPublicKey,
      algorithm: key.algorithm,
      status: 'active',
      createdAt: Date.now(),
      rotatedAt: null,
      useCounter: 0
    };

    this.keys.set(newId, replacement);
    return {
      oldQuantumKeyId: quantumKeyId,
      newQuantumKeyId: newId,
      newPublicKey: newPublicKey,
      status: replacement.status
    };
  }

  getQuantumKeyStatus(quantumKeyId) {
    const key = this.keys.get(quantumKeyId);
    if (!key) {
      throw new Error('Unknown quantum key');
    }

    return {
      quantumKeyId,
      publicKey: key.publicKey,
      algorithm: key.algorithm,
      postQuantum: false,
      status: key.status,
      createdAt: key.createdAt,
      rotatedAt: key.rotatedAt,
      useCounter: key.useCounter
    };
  }

  signPayload(quantumKeyId, payload) {
    const key = this.keys.get(quantumKeyId);
    if (!key || key.status !== 'active') {
      throw new Error('Quantum key unavailable');
    }

    const serialized = stableStringify(payload);
    const signature = crypto
      .createHmac('sha256', key.secret)
      .update(serialized)
      .digest('hex');

    key.useCounter += 1;
    return signature;
  }

  verifySignature(quantumKeyId, payload, signature) {
    const key = this.keys.get(quantumKeyId);
    if (!key) {
      return false;
    }

    const expected = crypto
      .createHmac('sha256', key.secret)
      .update(stableStringify(payload))
      .digest('hex');

    try {
      return crypto.timingSafeEqual(
        Buffer.from(expected, 'hex'),
        Buffer.from(signature, 'hex')
      );
    } catch {
      return false;
    }
  }
}

export class FermionWallet {
  // `now` returns milliseconds (the contract uses block.timestamp seconds).
  constructor(ownerAddress, { now = Date.now } = {}) {
    this.ownerAddress = ownerAddress;
    this.now = now;
    this.quantumKeys = new QuantumKeyManager();
    this.preApprovals = new Map();
    this.usedNonces = new Set();
  }

  generateQuantumKeyPair() {
    return this.quantumKeys.generateQuantumKeyPair();
  }

  rotateQuantumKey(quantumKeyId) {
    return this.quantumKeys.rotateQuantumKey(quantumKeyId);
  }

  getQuantumKeyStatus(quantumKeyId) {
    return this.quantumKeys.getQuantumKeyStatus(quantumKeyId);
  }

  approve(token, spender, amount) {
    return token.approve(this.ownerAddress, spender, amount);
  }

  static #signedPayload(a) {
    return {
      token: a.token.address,
      recipient: a.recipient,
      amount: a.amount,
      validFrom: a.validFrom,
      validTo: a.validTo,
      nonce: a.nonce,
      quantumKeyId: a.quantumKeyId,
      policyHash: a.policyHash
    };
  }

  // TRANSFER-class pre-approval: `recipient` receives exactly `amount` of `token`
  // from this wallet, once, inside [validFrom, validTo] (ms, inclusive).
  createPreApproval({ token, recipient, spender, amount, validFrom, validTo, nonce, quantumKeyId, policyHash }) {
    if (recipient === undefined && spender !== undefined) {
      throw new Error('`spender` was renamed to `recipient`: a pre-approval pays exactly this recipient');
    }
    if (!(token instanceof ERC20Token) || !token.address) {
      throw new Error('Invalid token');
    }
    if (!recipient) {
      throw new Error('Invalid recipient');
    }
    const key = this.quantumKeys.keys.get(quantumKeyId);
    if (!key || key.status !== 'active') {
      throw new Error('Quantum key unavailable for pre-approval');
    }

    const value = toUint(amount);
    const from = Number(validFrom);
    const to = Number(validTo);
    if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from || to - from < MIN_WINDOW_MS || to <= this.now()) {
      throw new Error(`Invalid window: need validTo > now and validTo - validFrom >= ${MIN_WINDOW_MS} ms`);
    }
    const nonceKey = String(nonce);
    if (this.usedNonces.has(nonceKey)) {
      throw new Error(`Pre-approval with nonce "${nonceKey}" already exists`);
    }

    const approval = {
      token,
      recipient,
      amount: value.toString(),
      validFrom: from,
      validTo: to,
      nonce: nonceKey,
      quantumKeyId,
      policyHash
    };
    const signature = this.quantumKeys.signPayload(quantumKeyId, FermionWallet.#signedPayload(approval));
    const preApprovalId = `pa-${crypto.randomUUID()}`;

    this.usedNonces.add(nonceKey);
    this.preApprovals.set(preApprovalId, {
      id: preApprovalId,
      ...approval,
      signatureAlgorithm: DEMO_SIGNATURE_ALGORITHM,
      signature,
      createdAt: this.now(),
      status: 'active'
    });

    return { preApprovalId, ...approval, signatureAlgorithm: DEMO_SIGNATURE_ALGORITHM, signature };
  }

  validatePreApproval(preApprovalId) {
    const approval = this.preApprovals.get(preApprovalId);
    if (!approval) {
      return { valid: false, reason: 'Unknown pre-approval' };
    }

    if (approval.status !== 'active') {
      return { valid: false, reason: `Pre-approval ${approval.status}` };
    }

    const now = this.now();
    if (now < approval.validFrom) {
      return { valid: false, reason: 'Pre-approval not yet valid' };
    }
    if (now > approval.validTo) {
      return { valid: false, reason: 'Pre-approval expired' };
    }

    let valid = false;
    try {
      valid = this.quantumKeys.verifySignature(
        approval.quantumKeyId,
        FermionWallet.#signedPayload(approval),
        approval.signature
      );
    } catch {
      valid = false;
    }
    if (!valid) {
      return { valid: false, reason: `Invalid ${DEMO_SIGNATURE_ALGORITHM} signature` };
    }

    return { valid: true, preApproval: approval };
  }

  // Mirrors the Guard's TRANSFER match: token, recipient and amount must all equal the
  // signed values (no partial spends); the approval is consumed on success.
  executePreApprovedTransfer(preApprovalId, recipient, amount) {
    const result = this.validatePreApproval(preApprovalId);
    if (!result.valid) {
      throw new Error(result.reason);
    }

    const approval = result.preApproval;
    const requestedAmount = toUint(amount);

    if (recipient !== approval.recipient) {
      throw new Error('Transfer recipient does not match the pre-approved recipient');
    }
    if (requestedAmount !== BigInt(approval.amount)) {
      throw new Error('Transfer amount does not match the pre-approved amount');
    }

    const token = approval.token;
    if (token.balanceOf(this.ownerAddress) < requestedAmount) {
      throw new Error('Insufficient wallet balance');
    }

    token.transfer(this.ownerAddress, recipient, requestedAmount);
    approval.status = 'used';

    return {
      preApprovalId,
      recipient,
      amount: requestedAmount.toString(),
      status: 'success'
    };
  }

  revokePreApproval(preApprovalId) {
    const approval = this.preApprovals.get(preApprovalId);
    if (!approval) {
      throw new Error('Unknown pre-approval');
    }
    if (approval.status !== 'active') {
      throw new Error(`Pre-approval ${approval.status}: not revocable`);
    }

    approval.status = 'revoked';
    return { preApprovalId, status: 'revoked' };
  }
}

export default FermionWallet;
