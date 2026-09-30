// Record the FermionGuard product flow on the real Safe{Wallet}, as frames for a GIF.
//
// Drives the same flow as e2e.js — the one a treasury team actually performs —
// and captures a frame at each beat:
//   1. an owner signs an ERC-20 transfer with Safe{Wallet}'s own Send flow
//   2. executing it fails: the Guard refuses a transfer with no quantum approval
//   3. the FermionGuard Safe App shows the transfer, reviewed field by field
//   4. the Quantum Administrator pages through the device and approves
//   5. the same transfer now executes from Safe{Wallet}'s queue
//
// Frames and their hold times land in <OUT>/frames.json; make_gif.py turns them
// into assets/fermionguard-demo.gif. Nothing here is staged: every frame is a
// screenshot of the running stack (demo/wallet/docker-compose.yml).
//
//   cd demo/wallet/e2e && npm ci && node record.js
// Env: CHROME, WALLET_URL, APP_URL, SAFE_ADDRESS, AMOUNT, OUT.
const crypto = require('crypto');
const fs = require('fs');
const { chromium } = require('playwright-core');

const WALLET = process.env.WALLET_URL || 'http://localhost:8000';
const APP = process.env.APP_URL || 'http://localhost:8001/safe-app';
const APP_ORIGIN = new URL(APP).origin;
const OWNER_PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'; // anvil #1
const SAFE = process.env.SAFE_ADDRESS || '0x8E3fd7B315486ce7Ea44A6E5129046148f807D49';
const TOKEN = '0x5FbDB2315678afecb367f032d93F642f64180aa3'; // dUSD
const AMOUNT = process.env.AMOUNT || '250000';
const RECIPIENT = '0x' + crypto.randomBytes(20).toString('hex');
const OUT = process.env.OUT || 'frames';

// The browser is sized so that a 900px-wide GIF is still readable.
const VIEWPORT = { width: 1120, height: 820 };

const step = msg => console.log(`[rec] ${msg}`);
const fail = msg => { throw new Error(msg); };

const frames = [];
/// Capture one frame. `hold` is how long the GIF rests on it, in milliseconds.
async function cap(page, name, hold, caption, device) {
  const file = `${String(frames.length).padStart(3, '0')}-${name}.png`;
  await page.screenshot({ path: `${OUT}/${file}` });
  const frame = { file, hold, caption };
  if (device) {
    frame.device = file.replace('.png', '-device.png');
    await device.screenshot({ path: `${OUT}/${frame.device}` });
  }
  frames.push(frame);
  step(`frame ${file}`);
}

async function rpc(method, params) {
  const r = await fetch(`${WALLET}/rpc`, {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id: 1, method, params})});
  return (await r.json()).result;
}
async function balanceOf(addr) {
  const data = '0x70a08231' + addr.slice(2).toLowerCase().padStart(64, '0');
  return BigInt(await rpc('eth_call', [{to: TOKEN, data}, 'latest']));
}
async function appApi(what) {
  return (await fetch(`${APP_ORIGIN}/api/v1/safes/${SAFE}/${what}`)).json();
}
async function clickIfShown(locator, ms = 3000) {
  try { await locator.waitFor({ state: 'visible', timeout: ms }); } catch { return false; }
  await locator.click();
  return true;
}
async function trustSafeIfAsked(page) {
  if (await clickIfShown(page.getByRole('button', { name: 'Trust this Safe' }), 5000)) {
    await page.getByPlaceholder('Enter a name for this Safe').fill('Treasury');
    await page.getByRole('button', { name: 'Confirm' }).click();
  }
}
async function executeFromQueue(page) {
  await page.goto(`${WALLET}/transactions/queue?safe=fwdemo:${SAFE}`, { waitUntil: 'networkidle' });
  await clickIfShown(page.getByRole('button', { name: 'Accept all' }));
  await page.getByRole('button', { name: 'Execute', exact: true }).first().click({ timeout: 30000 });
  await trustSafeIfAsked(page);
  await page.getByRole('button', { name: 'Continue', exact: true }).click({ timeout: 30000 });
  const execute = page.getByRole('button', { name: 'Execute', exact: true }).last();
  await execute.waitFor({ timeout: 30000 });
  await page.waitForTimeout(4000); // let the gas estimation / simulation settle
  return execute;
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const st = await appApi('status');
  if (!st.protected || !st.key) fail('the demo Safe is not protected by the FermionGuard');
  if (st.key.leavesLeft < 1) fail('the quantum key has no one-time signatures left; reset the stack');
  step(`Safe ${SAFE}, ${st.key.leavesLeft} signatures left; paying ${AMOUNT} dUSD to ${RECIPIENT}`);

  const browser = await chromium.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true });
  const ctx = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 1 });
  const page = await ctx.newPage();
  try {
    step('connect an owner with the "Private key" wallet');
    await page.goto(`${WALLET}/home?safe=fwdemo:${SAFE}`, { waitUntil: 'networkidle', timeout: 90000 });
    await clickIfShown(page.getByRole('button', { name: 'Accept all' }), 20000);
    await page.getByRole('button', { name: /Connect wallet/i }).first().click();
    await page.getByText('Private key', { exact: true }).click();
    await page.locator('input[type="password"], input[type="text"]').last().fill(OWNER_PK);
    await page.getByRole('button', { name: /connect/i }).last().click();
    await page.getByText(/0x7099/i).first().waitFor({ timeout: 20000 });
    await page.waitForTimeout(2000);
    await cap(page, 'home', 1900, 'A real Safe, in the real Safe{Wallet}. 250,000 dUSD to move.');

    step('create the transfer with Safe{Wallet} Send and sign it (no execution)');
    await page.getByRole('button', { name: 'Send' }).first().click();
    await trustSafeIfAsked(page);
    await page.locator('input[name="recipients.0.recipient"]').fill(RECIPIENT);
    await page.getByTestId('token-item').first().click();
    await page.getByRole('option', { name: /Demo USD/ }).click();
    await page.locator('input[name="recipients.0.amount"]').fill(AMOUNT);
    await page.waitForTimeout(1200);
    await cap(page, 'send', 1900, 'The owners sign it exactly as they do today.');
    await page.getByRole('button', { name: 'Next' }).click();
    await page.getByRole('button', { name: 'Continue' }).click({ timeout: 30000 });
    const split = page.locator('button[aria-haspopup="true"], button[aria-haspopup="menu"]');
    await page.waitForTimeout(2000);
    if (await split.count()) {  // next in line: Safe{Wallet} offers Execute; pick Sign
      await split.last().click();
      await page.getByRole('menuitem', { name: 'Sign' }).click();
    }
    await page.getByRole('button', { name: 'Sign' }).last().click({ timeout: 30000 });
    let queued = null;
    for (let i = 0; i < 60 && !queued; i++) {
      const q = await appApi('queue');
      queued = (q.transactions || []).find(t => t.recipient === RECIPIENT.toLowerCase());
      if (!queued) await page.waitForTimeout(1000);
    }
    if (!queued) fail('the signed transfer never reached the Safe Transaction Service');
    step(`queued as Safe tx #${queued.nonce} (${queued.safeTxHash.slice(0, 10)}…), status ${queued.status}`);

    step('execute without a quantum approval: Safe{Wallet} must warn and fail');
    let execute = await executeFromQueue(page);
    if (!(await page.innerText('body')).includes('will most likely fail')) {
      fail('Safe{Wallet} did not flag the unapproved transfer');
    }
    await page.getByText('will most likely fail').first().scrollIntoViewIfNeeded();
    await page.waitForTimeout(800);
    await cap(page, 'warned', 2400, 'Fully signed — and Safe{Wallet} already says it will most likely fail.');
    await execute.click();
    await page.getByText(/Execution failed|Error submitting the transaction/).first().waitFor({ timeout: 30000 });
    await page.waitForTimeout(1500);
    await cap(page, 'blocked', 2700, 'The Guard refuses it on-chain. Owner signatures are no longer enough.');
    if ((await balanceOf(RECIPIENT)) !== 0n) fail('the unapproved transfer moved funds');
    step('blocked by the Guard, nothing paid');

    step('approve it in the FermionGuard Safe App, signing on the Ledger');
    await page.goto(`${WALLET}/apps/open?safe=fwdemo:${SAFE}&appUrl=${encodeURIComponent(APP)}`, { waitUntil: 'networkidle' });
    const app = page.frameLocator('iframe').first();
    const row = app.locator(`[data-row="${queued.safeTxHash}"]`);
    for (let i = 0; !(await row.isVisible().catch(() => false)); i++) {
      if (i > 120) fail('the transfer did not appear in the FermionGuard queue');
      await clickIfShown(page.getByRole('button', { name: 'Accept all' }), 100);
      if (await clickIfShown(page.getByText('I have read and understood'), 100)) {
        await page.getByRole('button', { name: 'Continue' }).click();
      }
      await page.waitForTimeout(500);
    }
    await page.waitForTimeout(1500);
    await cap(page, 'app', 2200, 'FermionGuard, inside Safe{Wallet}: the transfer needs a second authorization.');
    await row.getByRole('button', { name: 'Review' }).click();
    await page.waitForTimeout(1200);
    await cap(page, 'review', 2800, 'Every field re-derived from two sources before anything is signed.');
    await row.getByRole('button', { name: 'Sign on Ledger' }).click();
    await page.waitForTimeout(1200);

    // The device window: one frame per screen the Quantum Administrator reads.
    const devicePage = await ctx.newPage();
    await devicePage.goto(`${APP_ORIGIN}/ledger`);
    const widget = devicePage.locator('body > div').first();
    await devicePage.locator('#next:not([disabled])').waitFor({ timeout: 30000 });
    await page.bringToFront();
    const deviceCaption = 'The Quantum Administrator reads every field on the device itself.';
    await cap(page, 'device', 900, deviceCaption, widget);
    for (let i = 0; await devicePage.locator('#next:not([disabled])').count(); i++) {
      if (i > 12) fail('the device never reached its last screen');
      await devicePage.locator('#next').click();
      await devicePage.waitForTimeout(400);
      await cap(page, 'device', 900, deviceCaption, widget);
    }
    await devicePage.locator('#approve:not([disabled])').click({ timeout: 10000 });
    await devicePage.waitForTimeout(800);
    await cap(page, 'device-approve', 2000,
      'Approve: one one-time XMSS signature, spent on this transaction and no other.', widget);
    await row.getByText('Ready to execute').waitFor({ timeout: 120000 });
    await page.waitForTimeout(1200);
    await cap(page, 'approved', 2400, 'Pre-approval recorded on-chain, pinned to this exact Safe transaction.');
    await devicePage.close();
    step('approved on the Ledger; the Guard holds a pre-approval pinned to this Safe tx');

    step('execute from Safe{Wallet}: it must go through');
    execute = await executeFromQueue(page);
    if ((await page.innerText('body')).includes('will most likely fail')) {
      fail('Safe{Wallet} still predicts failure after the pre-approval');
    }
    await execute.click();
    await page.getByText(/Transaction was processed|Transaction is executed|Successfully executed/)
      .first().waitFor({ timeout: 60000 });

    // Wait for the payment to actually land before the closing frames, so the last
    // thing the recording shows is a finished transfer and not a spinner.
    const want = BigInt(AMOUNT) * 10n ** 18n;
    let got = 0n;
    for (let i = 0; i < 30 && got !== want; i++) {
      got = await balanceOf(RECIPIENT);
      if (got !== want) await page.waitForTimeout(1000);
    }
    if (got !== want) fail(`recipient balance ${got}, expected ${want}`);
    await page.waitForTimeout(3000);
    await cap(page, 'executed', 3000, 'Now — and only now — the transfer goes through.');

    await clickIfShown(page.getByRole('button', { name: 'Finish' }), 10000);
    await page.goto(`${WALLET}/transactions/history?safe=fwdemo:${SAFE}`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(4000);
    await cap(page, 'history', 3600,
      'Two independent cryptographic domains. One transfer. Exactly 250,000 dUSD.');

    fs.writeFileSync(`${OUT}/frames.json`, JSON.stringify({ amount: AMOUNT, recipient: RECIPIENT,
      safeTxHash: queued.safeTxHash, frames }, null, 2));
    step(`PASS: ${frames.length} frames in ${OUT}; paid exactly ${AMOUNT} dUSD after the Ledger approval`);
  } catch (e) {
    await page.screenshot({ path: `${OUT}/failure.png` }).catch(() => {});
    throw e;
  } finally {
    await browser.close();
  }
})().catch(e => {
  console.error(`[rec] FAIL: ${e.message}`);
  process.exit(1);
});
