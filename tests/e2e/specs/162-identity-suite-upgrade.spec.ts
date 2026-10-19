import { execSync } from 'node:child_process'
import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount, signIn } from '../fixtures/apps'
import { createFolder, itemAction } from '../fixtures/drive'

// Post-quantum Drive keys (docs/plans/pq-shares.md): an account from before
// them (identity suite 1, an X25519 key) gets nothing shared to it, and says
// why; its next sign-in moves it to X-Wing keys, and then it can be shared
// with. Making an account "from before" takes the stack's database
// (E2E_PSQL, tests/e2e/README.md), as the backup gate seeds one.

const PASSWORD = 'Deneme123*IdentitySuiteSpec'

function sql(statement: string): string {
  return execSync(process.env.E2E_PSQL!, { input: `${statement}\n`, encoding: 'utf8' })
}

test('an account from before X-Wing keys is shared with once it has signed in again', async ({ browser }) => {
  test.skip(!process.env.E2E_PSQL, 'E2E_PSQL: a command that runs SQL from its stdin against the test stack database')
  test.slow()
  const tag = Date.now()
  const owner = newAccount('suiteowner', PASSWORD)
  const old = newAccount('suiteold', PASSWORD)
  const contextOwner = await browser.newContext()
  await registerAccount(contextOwner, owner)
  await registerAccount(await browser.newContext(), old)

  // As the account was before X-Wing: suite 1, a 32-byte X25519 key.
  sql(
    `UPDATE users SET identity_suite = 1, public_key = '${Buffer.alloc(32).toString('base64')}' WHERE username = '${old.username}';`,
  )
  const suite = () =>
    /suite=(\d+) bytes=(\d+)/.exec(
      sql(
        `SELECT 'suite=' || identity_suite || ' bytes=' || length(decode(public_key, 'base64')) FROM users WHERE username = '${old.username}';`,
      ),
    )?.slice(1, 3)
  expect(suite()).toEqual(['1', '32'])

  // Nothing is sealed to it: the owner is told why, in words.
  const drive = await openDrive(contextOwner)
  const folder = `suite-${tag}`
  await createFolder(drive, folder)
  let shares = 0
  drive.on('request', (request) => {
    if (/\/api\/collections\/[^/]+\/share$/.test(new URL(request.url()).pathname) && request.method() === 'POST') shares += 1
  })
  await itemAction(drive, folder, 'Share')
  const dialog = drive.getByRole('dialog')
  await dialog.getByLabel('Kutup address').fill(old.address)
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(dialog.getByRole('alert')).toContainText('needs to sign in to Kutup once more', { timeout: 30_000 })
  expect(shares).toBe(0)
  await drive.keyboard.press('Escape')

  // Its next sign-in moves it to X-Wing keys, once.
  await signIn(await browser.newContext(), old)
  await expect.poll(suite, { timeout: 30_000 }).toEqual(['2', '1216'])

  // Now the share goes through.
  let shared = 0
  drive.on('response', (response) => {
    if (/\/api\/collections\/[^/]+\/share$/.test(new URL(response.url()).pathname) && response.request().method() === 'POST') {
      shared = response.status()
    }
  })
  await drive.reload()
  await itemAction(drive, folder, 'Share')
  await dialog.getByLabel('Kutup address').fill(old.address)
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect.poll(() => shared, { timeout: 30_000 }).toBe(201)
})
