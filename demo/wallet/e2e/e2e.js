// End-to-end test of FermionGuard on the real Safe{Wallet}.
//
// Drives headless Chrome through the product flow against a running stack
// (demo/wallet/docker-compose.yml), exactly as a treasury team would:
//   1. connect an owner with Safe{Wallet}'s "Private key" wallet
//   2. create a dUSD transfer with Safe{Wallet}'s own Send flow and sign it
//   3. try to execute it from Safe{Wallet}'s queue -> the Guard blocks it
//   4. open the FermionGuard Safe App: the transfer is listed as needing
//      quantum approval; review it and sign on the Ledger (the device window)
//   5. execute it from Safe{Wallet}'s queue -> it goes through, exact amount paid
//
//   cd demo/wallet/e2e && npm ci && node e2e.js
// Env: CHROME (browser binary), WALLET_URL, APP_URL, SAFE_ADDRESS, AMOUNT, SCREENSHOTS.
const crypto = require('crypto');
const { chromium } = require('playwright-core');

const WALLET = process.env.WALLET_URL || 'http://localhost:8000';
const APP = process.env.APP_URL || 'http://localhost:8001/safe-app';
const APP_ORIGIN = new URL(APP).origin;
const OWNER_PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'; // anvil #1
const SAFE = process.env.SAFE_ADDRESS || '0x8E3fd7B315486ce7Ea44A6E5129046148f807D49';
const TOKEN = '0x5FbDB2315678afecb367f032d93F642f64180aa3'; // dUSD
// Random amount and fresh recipient: a run never matches anything left on a reused stack.
const AMOUNT = process.env.AMOUNT || String(1 + crypto.randomInt(999));
const RECIPIENT = '0x' + crypto.randomBytes(20).toString('hex');
const SHOTS = process.env.SCREENSHOTS;

const step = msg => console.log(`[e2e] ${msg}`);
const fail = msg => { throw new Error(msg); };

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
async function shot(page, name) {
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` });
}
// Dismiss dialogs that may appear late (cookie banner) without failing when absent.
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

// Open the queued transaction in Safe{Wallet}'s queue and press Execute.
async function executeFromQueue(page) {
  await page.goto(`${WALLET}/transactions/queue?safe=fwdemo:${SAFE}`, { waitUntil: 'networkidle' });
  await clickIfShown(page.getByRole('button', { name: 'Accept all' }));
  await page.getByRole('button', { name: 'Execute', exact: true }).first().click({ timeout: 30000 });
  await trustSafeIfAsked(page);
  await page.getByRole('button', { name: 'Continue', exact: true }).click({ timeout: 30000 });
  const execute = page.getByRole('button', { name: 'Execute', exact: true }).last();
  await execute.waitFor({ timeout: 30000 });
  await page.waitForTimeout(3000); // let the gas estimation / simulation settle
  return execute;
}

(async () => {
  const st = await appApi('status');
  if (!st.protected || !st.key) fail('the demo Safe is not protected by the FermionGuard');
  if (st.key.leavesLeft < 1) {
    fail('the quantum key has no one-time signatures left. Reset the stack: ' +
      'docker compose down -v && docker compose up -d --wait');
  }
  step(`Safe ${SAFE} protected, ${st.key.leavesLeft} signatures left; paying ${AMOUNT} dUSD to ${RECIPIENT}`);

  const browser = await chromium.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 1000 } });
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

    step('create the transfer with Safe{Wallet} Send and sign it (no execution)');
    await page.getByRole('button', { name: 'Send' }).first().click();
    await trustSafeIfAsked(page);
    await page.locator('input[name="recipients.0.recipient"]').fill(RECIPIENT);
    await page.getByTestId('token-item').first().click();
    await page.getByRole('option', { name: /Demo USD/ }).click();
    await page.locator('input[name="recipients.0.amount"]').fill(AMOUNT);
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
    if (queued.status !== 'needs_approval') fail(`expected needs_approval, got ${queued.status}`);

    step('execute without a quantum approval: Safe{Wallet} must warn and fail');
    let execute = await executeFromQueue(page);
    if (!(await page.innerText('body')).includes('will most likely fail')) {
      fail('Safe{Wallet} did not flag the unapproved transfer');
    }
    await execute.click();
    await page.getByText(/Execution failed|Error submitting the transaction/).first().waitFor({ timeout: 30000 });
    await shot(page, '1-blocked');
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
    await row.getByRole('button', { name: 'Review' }).click();
    await row.getByRole('button', { name: 'Sign on Ledger' }).click();
    await shot(page, '2-review');

    const device = await ctx.newPage();
    await device.goto(`${APP_ORIGIN}/ledger`);
    await device.locator('#next:not([disabled])').waitFor({ timeout: 30000 });
    while (await device.locator('#next:not([disabled])').count()) {
      await device.locator('#next').click();
      await device.waitForTimeout(300);
    }
    await device.locator('#approve:not([disabled])').click({ timeout: 10000 });
    await row.getByText('Ready to execute').waitFor({ timeout: 120000 });
    await shot(page, '3-approved');
    await device.close();
    step('approved on the Ledger; the Guard holds a pre-approval pinned to this Safe tx');

    step('execute from Safe{Wallet}: it must go through');
    execute = await executeFromQueue(page);
    if ((await page.innerText('body')).includes('will most likely fail')) {
      fail('Safe{Wallet} still predicts failure after the pre-approval');
    }
    await execute.click();
    await page.getByText(/Transaction was processed|Transaction is executed|Successfully executed/)
      .first().waitFor({ timeout: 60000 });
    await shot(page, '4-executed');

    const want = BigInt(AMOUNT) * 10n ** 18n;
    let got = 0n;
    for (let i = 0; i < 20 && got !== want; i++) {
      got = await balanceOf(RECIPIENT);
      if (got !== want) await page.waitForTimeout(1000);
    }
    if (got !== want) fail(`recipient balance ${got}, expected ${want}`);
    const approvals = (await appApi('approvals')).approvals || [];
    const used = approvals.find(a => a.safeTxHash === queued.safeTxHash);
    if (!used || used.status !== 'used') fail('the pre-approval was not recorded as used');
    step(`PASS: blocked without approval; paid exactly ${AMOUNT} dUSD after the Ledger approval`);
  } catch (e) {
    await shot(page, 'failure');
    throw e;
  } finally {
    await browser.close();
  }
})().catch(e => {
  console.error(`[e2e] FAIL: ${e.message}`);
  process.exit(1);
});
