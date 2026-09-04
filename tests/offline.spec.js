// Phase 5 -- prove the offline system works, every deploy, instead of relying
// on a human remembering to click through it by hand after each change.
//
// NOT YET RUN. This machine has no Node/Playwright installed (`node` and
// `docker` are both absent here) -- written as source so it exists as an
// exact, versioned spec of what "the offline system still works" means, and
// so it's a one-time `npm install` away from actually running, rather than
// leaving Phase 5 unwritten because this session's environment couldn't
// execute it. Run it against a staging deployment, never against the NAS the
// team is actively using.
//
//   npm install -D @playwright/test
//   npx playwright install chromium
//   WLM_URL=https://<staging-host>:2513 WLM_PASSWORD=... npx playwright test
//
// Every prior bug in this feature (see the commit history for both this repo
// and wlm-sorting-service) was found by a *real* disconnect against a *real*
// browser profile -- automated testing here uses Playwright's genuine
// context.setOffline(true), which actually severs the browser's network
// stack, not a simulated flag flip -- to stay honest to that lesson.

const { test, expect } = require('@playwright/test');

const BASE_URL = process.env.WLM_URL || 'https://localhost:2513';
const PASSWORD = process.env.WLM_PASSWORD || '';
const SANDBOX_PARENT = process.env.WLM_TEST_SANDBOX || '000'; // a folder safe to create/delete test children in

test.beforeEach(async ({ page }) => {
  await page.goto(`${BASE_URL}/login`);
  await page.fill('input[name=password], input[type=password]', PASSWORD);
  await page.click('button:has-text("Sign in"), input[type=submit]');
  await page.waitForLoadState('networkidle');
});

test('mkdir queues offline, shows as a pending folder, and replays for real', async ({ page, context }) => {
  const folderName = `PW_TEST_MKDIR_${Date.now()}`;

  await context.setOffline(true);
  // Give the app's own detection a moment -- 'immediate' network errors get
  // an 8s grace before the banner shows (see OFFLINE_GRACE_MS_FAST).
  await page.waitForTimeout(9000);
  await expect(page.locator('#offlineBanner')).toBeVisible();

  await page.evaluate(({ parent, name }) => {
    return window._sendOrQueue('mkdir', '/api/mkdir', { parent, names: [name] });
  }, { parent: SANDBOX_PARENT, name: folderName });

  // The pending folder should render immediately, still offline, as a real
  // (if dimmed) folder-item -- this is the actual point of Phase 1's fix.
  const pendingEl = page.locator(`.folder-item.folder-pending-offline[data-path="${SANDBOX_PARENT}/${folderName}"]`);
  // May need to expand the parent folder in the tree first, depending on UI state.
  await expect(pendingEl).toBeVisible({ timeout: 5000 }).catch(async () => {
    await page.click(`.folder-item[data-path="${SANDBOX_PARENT}"] .f-chevron`);
    await expect(pendingEl).toBeVisible();
  });

  await context.setOffline(false);
  // Reconnect prompt should appear and list the queued action.
  await expect(page.locator('text=Connection restored')).toBeVisible({ timeout: 10000 });
  await page.click('#_reconnectApplyBtn');
  await expect(page.locator('text=Offline changes applied')).toBeVisible({ timeout: 15000 });
  await page.click('#_replayDismissBtn');

  // The folder must now exist for real, not just in the UI.
  const listing = await page.evaluate((parent) => fetch(`/api/ls/${parent}`).then(r => r.json()), SANDBOX_PARENT);
  expect(listing.some(f => f.name === folderName)).toBe(true);

  // Cleanup -- real delete, while online.
  await page.evaluate(({ parent, name }) => fetch('/api/delete', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ paths: [`${parent}/${name}`], folder: true }),
  }), { parent: SANDBOX_PARENT, name: folderName });
});

test('delete queues offline and the item disappears from the grid immediately', async ({ page, context }) => {
  // Requires a throwaway file already present under SANDBOX_PARENT for this
  // test to delete -- left as a fixture concern for whoever wires this into
  // CI, since creating a real media file from scratch here is out of scope
  // for what this spec is demonstrating.
  test.skip(!process.env.WLM_TEST_FIXTURE_FILE, 'set WLM_TEST_FIXTURE_FILE to a real, disposable file path to run this');
  const filePath = process.env.WLM_TEST_FIXTURE_FILE;

  await page.evaluate((p) => window.selectFolder(p.split('/').slice(0, -1).join('/'), null), filePath);
  await page.waitForTimeout(1000);

  await context.setOffline(true);
  await page.waitForTimeout(9000);

  await page.evaluate((p) => window._sendOrQueue('delete', '/api/delete', { paths: [p], folder: false }), filePath);
  await expect(page.locator(`.grid-cell[data-path="${filePath}"]`)).toHaveCount(0);

  await context.setOffline(false);
  await expect(page.locator('text=Connection restored')).toBeVisible({ timeout: 10000 });
  await page.click('#_reconnectApplyBtn');
  await expect(page.locator('text=Offline changes applied')).toBeVisible({ timeout: 15000 });
});

test('rate/flag queues offline instead of being silently dropped', async ({ page }) => {
  // Regression test for the exact bug Phase 1 fixed: _applyRatingUpdate used
  // to fire-and-forget with no queueing at all, so a rating set offline was
  // simply lost. This checks the queue directly rather than the UI badge,
  // since the badge already updates optimistically regardless of whether
  // the underlying request is queued or just discarded.
  await page.context().setOffline(true);
  await page.waitForTimeout(9000);

  const queueLengthBefore = await page.evaluate(() => window._offlineQueue.length);
  await page.evaluate(() => window._applyRatingUpdate([0], { rating: 3 }).catch(() => {}));
  const queueLengthAfter = await page.evaluate(() => window._offlineQueue.length);

  expect(queueLengthAfter).toBeGreaterThan(queueLengthBefore);
  await page.context().setOffline(false);
});

test('replay can be cancelled mid-way and un-applied actions are re-queued, not lost', async ({ page }) => {
  const names = ['PW_CANCEL_A', 'PW_CANCEL_B', 'PW_CANCEL_C'].map(n => `${n}_${Date.now()}`);

  await page.evaluate(({ parent, names }) => {
    window._offlineQueue = names.map(name => ({
      kind: 'mkdir', url: '/api/mkdir', body: { parent, names: [name] }, ts: Date.now(),
    }));
    window._saveOfflineQueue();
  }, { parent: SANDBOX_PARENT, names });

  // Fire the replay and cancel it on the very next tick -- exercises the
  // same race the real "Stop here" button hits when clicked quickly.
  await page.evaluate(() => {
    window.__replayPromise = window._replayOfflineQueue();
    window._replayCancelRequested = true;
  });
  await page.evaluate(() => window.__replayPromise);

  const remaining = await page.evaluate(() => window._offlineQueue.map(a => a.body.names[0]));
  expect(remaining.length).toBeGreaterThan(0);
  expect(remaining.length).toBeLessThan(names.length);

  // Cleanup: whatever actually got created for real.
  for (const name of names) {
    if (!remaining.includes(name)) {
      await page.evaluate(({ parent, name }) => fetch('/api/delete', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ paths: [`${parent}/${name}`], folder: true }),
      }), { parent: SANDBOX_PARENT, name });
    }
  }
  await page.evaluate(() => { window._offlineQueue = []; window._saveOfflineQueue(); });
});

test('a cold reload while genuinely offline still shows the app shell (Service Worker)', async ({ page, context }) => {
  await page.waitForTimeout(2000); // let the SW finish registering from the earlier page load
  await context.setOffline(true);
  await page.reload();
  // The shell (login-gated page or the app itself, depending on session
  // state) should still render from cache rather than a browser
  // "can't be reached" error page -- this is what the Service Worker is
  // specifically for.
  await expect(page.locator('body')).not.toContainText('can’t be reached');
  await context.setOffline(false);
});
