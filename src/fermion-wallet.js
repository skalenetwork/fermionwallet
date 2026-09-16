import crypto from 'node:crypto';

function stableStringify(value) {
  return JSON.stringify(value, Object.keys(value).sort());
}

export class ERC20Token {
  constructor(name, symbol) {
    this.name = name;
    this.symbol = symbol;
    this.balances = new Map();
    this.allowances = new Map();
  }

  mint(owner, amount) {
    const value = BigInt(amount);
    const next = (this.balances.get(owner) ?? 0n) + value;
    this.balances.set(owner, next);
    return next;
  }

  balanceOf(owner) {
    return this.balances.get(owner) ?? 0n;
  }

  approve(owner, spender, amount) {
    const value = BigInt(amount);
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
    const value = BigInt(amount);
    if (this.balanceOf(owner) < value) {
      throw new Error('Insufficient balance');
    }
    this.balances.set(owner, this.balanceOf(owner) - value);
    this.balances.set(to, this.balanceOf(to) + value);
    return true;
  }

  transferFrom(spender, from, to, amount) {
    const value = BigInt(amount);
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
    const quantumKeyId = `qk-${crypto.randomUUID()}`;
    const secret = crypto.randomBytes(32).toString('hex');
    const walletPublicKey = `pub-${crypto.randomBytes(16).toString('hex')}`;
    const key = {
      id: quantumKeyId,
      secret,
      publicKey: walletPublicKey,
      algorithm: 'hybrid-pqc',
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
  constructor(ownerAddress) {
    this.ownerAddress = ownerAddress;
    this.quantumKeys = new QuantumKeyManager();
    this.preApprovals = new Map();
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

  createPreApproval({ token, spender, amount, validFrom, validTo, nonce, quantumKeyId, policyHash }) {
    const key = this.quantumKeys.keys.get(quantumKeyId);
    if (!key || key.status !== 'active') {
      throw new Error('Quantum key unavailable for pre-approval');
    }

    const payload = {
      token,
      spender,
      amount: String(amount),
      validFrom: Number(validFrom),
      validTo: Number(validTo),
      nonce,
      quantumKeyId,
      policyHash
    };

    const signature = this.quantumKeys.signPayload(quantumKeyId, payload);
    const preApprovalId = `pa-${crypto.randomUUID()}`;

    this.preApprovals.set(preApprovalId, {
      id: preApprovalId,
      token,
      spender,
      amount: String(amount),
      validFrom: Number(validFrom),
      validTo: Number(validTo),
      nonce,
      quantumKeyId,
      policyHash,
      signature,
      createdAt: Date.now(),
      status: 'active'
    });

    return { preApprovalId, ...payload, signature };
  }

  validatePreApproval(preApprovalId) {
    const approval = this.preApprovals.get(preApprovalId);
    if (!approval) {
      return { valid: false, reason: 'Unknown pre-approval' };
    }

    if (approval.status !== 'active') {
      return { valid: false, reason: 'Pre-approval revoked or inactive' };
    }

    const now = Date.now();
    if (now < approval.validFrom || now > approval.validTo) {
      return { valid: false, reason: 'Pre-approval expired or not yet valid' };
    }

    const payload = {
      token: approval.token,
      spender: approval.spender,
      amount: approval.amount,
      validFrom: approval.validFrom,
      validTo: approval.validTo,
      nonce: approval.nonce,
      quantumKeyId: approval.quantumKeyId,
      policyHash: approval.policyHash
    };

    const valid = this.quantumKeys.verifySignature(approval.quantumKeyId, payload, approval.signature);
    if (!valid) {
      return { valid: false, reason: 'Invalid quantum signature' };
    }

    return { valid: true, preApproval: approval };
  }

  executePreApprovedTransfer(preApprovalId, recipient, amount) {
    const result = this.validatePreApproval(preApprovalId);
    if (!result.valid) {
      throw new Error(result.reason);
    }

    const approval = result.preApproval;
    const requestedAmount = BigInt(amount);
    const approvedAmount = BigInt(approval.amount);

    if (requestedAmount > approvedAmount) {
      throw new Error('Transfer exceeds pre-approved amount');
    }

    const token = approval.token;
    const ownerBalance = token.balanceOf(this.ownerAddress);
    if (ownerBalance < requestedAmount) {
      throw new Error('Insufficient wallet balance');
    }

    token.transfer(this.ownerAddress, recipient, requestedAmount);
    approval.status = 'consumed';

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

    approval.status = 'revoked';
    return { preApprovalId, status: 'revoked' };
  }
}

export default FermionWallet;
