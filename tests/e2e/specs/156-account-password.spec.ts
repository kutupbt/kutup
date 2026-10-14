import { createHmac } from 'node:crypto'
import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount, submitThroughRateLimit } from '../fixtures/apps'

// The password through OPAQUE (docs/plans/opaque.md): changing it in Account
// → Security, signing in with a second factor (the sign-in's export key waits
// in its worker for the code), and setting a new one with the recovery
// phrase. The old password stops working each time.

const FIRST = 'Deneme123*FirstOpaquePassword'
const SECOND = 'Deneme123*SecondOpaquePassword'
const THIRD = 'Deneme123*ThirdOpaquePassword'

/** The current TOTP code for a base32 secret (RFC 6238: SHA-1, 30 s, 6 digits). */
function totp(secret: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const char of secret.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(char).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g)!.map((byte) => parseInt(byte, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
  const mac = createHmac('sha1', key).update(counter).digest()
  const offset = mac[mac.length - 1] & 0x0f
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

async function signIn(page: Page, username: string, password: string, outcome: 'Welcome' | 'failed' | 'code') {
  await page.goto(appUrl('account', '/login'))
  await page.getByLabel('Username', { exact: true }).fill(username)
  await page.getByLabel('Password', { exact: true }).fill(password)
  const done =
    outcome === 'Welcome'
      ? page.getByRole('heading', { name: /^Welcome/ })
      : outcome === 'code'
        ? page.getByLabel('Authentication code')
        : page.getByRole('alert').filter({ hasText: 'Sign-in failed. Check your username and password.' })
  await submitThroughRateLimit(page, 'Sign in', done)
}

test('the password is changed, guarded by a second factor, and reset with the recovery phrase', async ({ browser }) => {
  test.slow()
  const account = newAccount('opaquepw', FIRST)
  const own = await browser.newContext()
  const phrase = await registerAccount(own, account)
  const page = await own.newPage()

  // Account → Security: a new password; the current one must be right.
  // A failed attempt clears every field, so each try types them all.
  await page.goto(appUrl('account', '/settings/security'))
  const passwords = (current: string) => async () => {
    await page.getByLabel('Current password').fill(current)
    await page.getByLabel('New password', { exact: true }).fill(SECOND)
    await page.getByLabel('Repeat password', { exact: true }).fill(SECOND)
  }
  await submitThroughRateLimit(page, 'Change password', page.getByText('Your current password is not right.'), passwords('Not*TheCurrentPassword1'))
  await expect(page.getByLabel('New password', { exact: true })).toHaveValue('')
  await submitThroughRateLimit(page, 'Change password', page.getByText('Password changed. Your other devices are signed out.').first(), passwords(FIRST))

  // A second factor, while signed in here.
  await page.getByRole('button', { name: 'Set up two-factor authentication' }).click()
  const manual = (await page.getByText('Or enter this key manually:').textContent()) ?? ''
  const secret = manual.replace('Or enter this key manually:', '').trim()
  expect(secret).toMatch(/^[A-Z2-7]+=*$/)
  await page.getByLabel('6-digit code').fill(totp(secret))
  await page.getByRole('button', { name: 'Verify and turn on' }).click()
  await expect(page.getByRole('button', { name: 'Turn off two-factor authentication' })).toBeVisible({ timeout: 30_000 })
  await own.close()

  // Elsewhere: the first password is gone; the second asks for the code, then signs in.
  const other = await browser.newContext()
  const tab = await other.newPage()
  await signIn(tab, account.username, FIRST, 'failed')
  await signIn(tab, account.username, SECOND, 'code')
  await tab.getByLabel('Authentication code').fill(totp(secret))
  await submitThroughRateLimit(tab, 'Verify', tab.getByRole('heading', { name: /^Welcome/ }))
  await other.close()

  // The recovery phrase sets a third password; the second stops working.
  const recovering = await browser.newContext()
  const recover = await recovering.newPage()
  await recover.goto(appUrl('account', '/recover'))
  await recover.getByLabel('Username', { exact: true }).fill(account.username)
  await recover.getByLabel('Recovery phrase').fill(phrase)
  await recover.getByLabel('New password', { exact: true }).fill(THIRD)
  await recover.getByLabel('Repeat password', { exact: true }).fill(THIRD)
  await submitThroughRateLimit(recover, 'Set new password', recover.getByRole('heading', { name: 'Password changed' }))
  await signIn(recover, account.username, SECOND, 'failed')
  await signIn(recover, account.username, THIRD, 'code')
  await recover.getByLabel('Authentication code').fill(totp(secret))
  await submitThroughRateLimit(recover, 'Verify', recover.getByRole('heading', { name: /^Welcome/ }))
  await recovering.close()
})
