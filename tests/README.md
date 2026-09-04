# Offline system tests

`offline.spec.js` is a Playwright end-to-end suite that exercises the
offline system by genuinely cutting the browser's network
(`context.setOffline(true)`), the same way the real bugs in this
feature's history were actually found.

**Not yet run in this repo's environment** — no Node.js/Playwright
installed on the machine this was written on. A one-time setup away
from running, not something left unwritten.

## Setup (once)

```
cd tests
npm install
npx playwright install chromium
```

## Running

Run this against **your own test instance** of the app (e.g. Ifti's
laptop during a deliberate test session, or your own machine running
`client_shell.py` in dev mode against a throwaway folder) — never
against a real client's machine while they're paying for a live
sorting session. `WLM_TEST_SANDBOX` must point at a folder that's
genuinely safe to create and delete test subfolders in; there's no
"000" convention on a client's own folder tree the way there is on
WLM's NAS, so this has to be set explicitly every time, not assumed.

```
WLM_URL=https://<hostname>.ts.net:2514 \
WLM_PASSWORD=Yellowmango1! \
WLM_TEST_SANDBOX=<a real, disposable subfolder in the test target's PHOTOS_DIR> \
npx playwright test
```

## Before every release

Run this before bumping `APP_VERSION` and cutting a new GitHub release
-- once published, the self-update mechanism pushes it to every
connected client automatically, so a regression here reaches real
client machines with nobody watching, not just WLM's own team.
