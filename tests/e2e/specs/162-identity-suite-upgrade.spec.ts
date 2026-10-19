import { execSync } from 'node:child_process'
import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount, signIn } from '../fixtures/apps'
import { openChat } from '../fixtures/chat'
import { createFolder, itemAction } from '../fixtures/drive'

// Post-quantum Drive keys (docs/plans/pq-shares.md): an account from before
// them (identity suite 1, an X25519 key, suite-1 Chat manifests) gets nothing
// shared to it, and says why; its next sign-in moves it to X-Wing keys, Chat
// starts and publishes its next manifest with them, and then it can be shared
// with. Making an account "from before" takes the stack's owner:
// E2E_SUITE1_ACCOUNT runs the dev tool that turns the account named by
// KUTUP_SUITE1_USERNAME/KUTUP_SUITE1_PASSWORD into a real suite-1 one, and
// E2E_PSQL reads the database (tests/e2e/README.md).

const PASSWORD = 'Deneme123*IdentitySuiteSpec'

function sql(statement: string): string {
  return execSync(process.env.E2E_PSQL!, { input: `${statement}\n`, encoding: 'utf8' })
}

test('an account from before X-Wing keys is shared with once it has signed in again', async ({ browser }) => {
  test.skip(
    !process.env.E2E_PSQL || !process.env.E2E_SUITE1_ACCOUNT,
    'E2E_PSQL and E2E_SUITE1_ACCOUNT: commands that read the test stack database and make a suite-1 account',
  )
  test.slow()
  const tag = Date.now()
  const owner = newAccount('suiteowner', PASSWORD)
  const old = newAccount('suiteold', PASSWORD)
  const contextOwner = await browser.newContext()
  await registerAccount(contextOwner, owner)

  // The old account has used Chat (a device and a manifest), then its
  // browser closes, and the account is made as it was before X-Wing keys.
  const contextOld = await browser.newContext()
  await registerAccount(contextOld, old)
  await openChat(contextOld)
  await contextOld.close()
  execSync(process.env.E2E_SUITE1_ACCOUNT!, {
    env: { ...process.env, KUTUP_SUITE1_USERNAME: old.username, KUTUP_SUITE1_PASSWORD: old.password },
    stdio: ['ignore', 'inherit', 'inherit'],
  })
  const facts = () =>
    /suite=(\d+) bytes=(\d+) manifest=(\d+)/.exec(
      sql(
        `SELECT 'suite=' || u.identity_suite || ' bytes=' || length(decode(u.public_key, 'base64')) || ' manifest=' || (m.manifest->'drive'->>'suite')
           FROM users u JOIN chat_device_manifests m ON m.user_id = u.id WHERE u.username = '${old.username}';`,
      ),
    )?.slice(1, 4)
  expect(facts()).toEqual(['1', '32', '1'])

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

  // Its next sign-in moves it to X-Wing keys, once; Chat starts, and its
  // next manifest carries them.
  const contextAgain = await browser.newContext()
  await signIn(contextAgain, old)
  await expect.poll(() => facts()?.slice(0, 2), { timeout: 30_000 }).toEqual(['2', '1216'])
  await openChat(contextAgain)
  await expect.poll(() => facts()?.[2], { timeout: 60_000 }).toBe('2')

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
  await contextAgain.close()
  await contextOwner.close()
})
