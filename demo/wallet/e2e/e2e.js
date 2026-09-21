// End-to-end test of the FermionWallet demo on the real Safe{Wallet}.
//
// Drives a headless Chrome through the whole story against a running stack
// (demo/wallet/docker-compose.yml):
//   1. connect the owner with Safe{Wallet}'s "Private key" wallet
//   2. open the FermionWallet Safe App, propose a payout, press Execute in
//      Safe{Wallet} -> it warns and fails (the Guard reverts it); nothing is paid
//   3. approve the payment on the simulated Ledger inside the Safe App
//   4. propose the same payout again -> Safe{Wallet} executes it; vendor is paid
//
//   cd demo/wallet/e2e && npm ci && node e2e.js
// Env: CHROME (browser binary), WALLET_URL, APP_URL, SAFE_ADDRESS, AMOUNT.
const { chromium } = require('playwright-core');

const WALLET = process.env.WALLET_URL || 'http://localhost:8000';
const APP = process.env.APP_URL || 'http://localhost:8001/safe-app';
const APP_ORIGIN = new URL(APP).origin;
const OWNER_PK = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'; // anvil #1
const AMOUNT = process.env.AMOUNT || '100';
const SHOTS = process.env.SCREENSHOTS; // optional directory for screenshots

const step = msg => console.log(`[e2e] ${msg}`);
const fail = msg => { throw new Error(msg); };

async function appState() {
  return (await fetch(`${APP_ORIGIN}/api/state`)).json();
}

// Click a dialog control if it shows up within `ms`; fresh browsers get the cookie
// banner and the Safe Apps disclaimer, returning ones don't.
async function clickIfShown(locator, ms = 20000) {
  try {
    await locator.waitFor({ state: 'visible', timeout: ms });
  } catch {
    return false;
  }
  await locator.click();
  return true;
}

async function openApp(page, safeParam) {
  await page.goto(`${WALLET}/apps/open?safe=${safeParam}&appUrl=${encodeURIComponent(APP)}`,
    { waitUntil: 'networkidle' });
  // Until the app shows, dismiss whatever Safe{Wallet} puts in front of it: the
  // Safe Apps disclaimer (first open) and the cookie banner (can reappear late).
  const app = page.frameLocator('iframe').first();
  const ready = app.getByText('Guard enforcing');
  const disclaimer = page.getByText('I have read and understood');
  const cookies = page.getByRole('button', { name: 'Accept all' });
  for (let i = 0; !(await ready.isVisible().catch(() => false)); i++) {
    if (i > 120) fail('the FermionWallet Safe App did not load');
    if (await cookies.isVisible().catch(() => false)) await cookies.click();
    if (await disclaimer.isVisible().catch(() => false)) {
      await disclaimer.click();
      await page.getByRole('button', { name: 'Continue' }).click();
    }
    await page.waitForTimeout(500);
  }
  await app.locator('#amount').fill(AMOUNT);
  return app;
}

async function shot(page, name) {
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` });
}

async function proposeInWallet(page, app, button) {
  await app.locator(button).click();
  // Safe{Wallet}'s own review. First use asks to trust the Safe.
  const trust = page.getByRole('button', { name: 'Trust this Safe' });
  const cont = page.locator('[data-testid="continue-sign-btn"]:not([disabled])');
  await Promise.race([trust.waitFor({ timeout: 30000 }), cont.waitFor({ timeout: 30000 })]);
  if (await trust.isVisible()) {
    await trust.click();
    await page.getByPlaceholder('Enter a name for this Safe').fill('FermionWallet demo Safe');
    await page.getByRole('button', { name: 'Confirm' }).click();
  }
  await cont.click({ timeout: 30000 });
  await page.getByRole('button', { name: 'Execute' }).last().waitFor({ timeout: 30000 });
  await page.waitForTimeout(3000); // let the gas estimation / simulation settle
}

(async () => {
  const s0 = await appState();
  const safe = process.env.SAFE_ADDRESS || s0.safe;
  const vendorBefore = BigInt(s0.vendorBalance);
  step(`Safe ${safe}, guard active: ${s0.guardActive}, vendor balance ${vendorBefore}`);
  if (!s0.guardActive) fail('Guard is not set on the demo Safe');

  const browser = await chromium.launch({
    executablePath: process.env.CHROME || '/usr/bin/google-chrome',
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1400, height: 1000 } });
  try {
    const safeParam = `fwdemo:${safe}`;
    step('connect the owner with Safe{Wallet} "Private key" wallet');
    await page.goto(`${WALLET}/home?safe=${safeParam}`, { waitUntil: 'networkidle', timeout: 90000 });
    await clickIfShown(page.getByRole('button', { name: 'Accept all' }));
    await page.getByRole('button', { name: /Connect wallet/i }).first().click();
    await page.getByText('Private key', { exact: true }).click();
    await page.locator('input[type="password"], input[type="text"]').last().fill(OWNER_PK);
    await page.getByRole('button', { name: /connect/i }).last().click();
    await page.getByText(/0x7099/i).first().waitFor({ timeout: 20000 });

    step('open the FermionWallet Safe App');
    const app = await openApp(page, safeParam);
    await shot(page, '1-app');

    step('owner-signed payout without a pre-approval: Safe{Wallet} must warn and fail');
    await proposeInWallet(page, app, '#btn-propose-1');
    const body1 = await page.innerText('body');
    if (!body1.includes('will most likely fail')) fail('Safe{Wallet} did not flag the unapproved payout');
    await page.getByRole('button', { name: 'Execute' }).last().click();
    await page.getByText(/Execution failed|Error submitting the transaction/).first().waitFor({ timeout: 30000 });
    await shot(page, '2-blocked');
    if (BigInt((await appState()).vendorBalance) !== vendorBefore) fail('unapproved payout moved funds');
    step('blocked by the Guard, nothing paid');
    await page.keyboard.press('Escape');
    const app2 = await openApp(page, safeParam);

    step('approve the payment on the simulated Ledger (page through all 8 screens)');
    await app2.locator('#btn-approve').click();
    await app2.locator('#dev-next:not([disabled])').waitFor({ timeout: 30000 });
    for (let i = 0; i < 7; i++) {
      await app2.locator('#dev-next').click();
      await page.waitForTimeout(250);
    }
    await app2.locator('#dev-approve:not([disabled])').click({ timeout: 10000 });
    await app2.locator('#out-2.good').waitFor({ timeout: 180000 });
    step((await app2.locator('#out-2').innerText()).split('\n')[0]);
    await shot(page, '3-approved');

    step('same payout again: Safe{Wallet} must execute it');
    await proposeInWallet(page, app2, '#btn-propose-3');
    if ((await page.innerText('body')).includes('will most likely fail')) {
      fail('Safe{Wallet} still predicts failure after the pre-approval');
    }
    await page.getByRole('button', { name: 'Execute' }).last().click();
    await page.getByText(/Transaction was processed|Transaction is executed|Successfully executed/)
      .first().waitFor({ timeout: 60000 });
    await shot(page, '4-executed');

    const want = vendorBefore + BigInt(AMOUNT);
    for (let i = 0; i < 20; i++) {
      if (BigInt((await appState()).vendorBalance) === want) break;
      await page.waitForTimeout(1000);
    }
    const got = BigInt((await appState()).vendorBalance);
    if (got !== want) fail(`vendor balance ${got}, expected ${want}`);
    step(`PASS: blocked without approval, paid ${AMOUNT} dUSD with it (vendor balance ${got})`);
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
