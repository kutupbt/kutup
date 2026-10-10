import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { expect, test } from '@playwright/test'
import { appOrigin, appUrl, newAccount, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*MailAddressKeysPassword'

/** WKD lives at the server's root, not under /api. */
function wkdUrl(local: string, hash = wkdHash(local)): string {
  const origin = (process.env.E2E_API_URL ?? appOrigin('account')).replace(/\/+$/, '')
  return `${origin}/.well-known/openpgpkey/hu/${hash}?l=${local}`
}

/** z-base-32 of SHA-1, as Web Key Directory hashes a local part. */
function wkdHash(local: string): string {
  const alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769'
  const bytes = createHash('sha1').update(local.toLowerCase()).digest()
  let out = ''
  let buffer = 0
  let bits = 0
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += alphabet[(buffer >> bits) & 31]
    }
  }
  if (bits > 0) out += alphabet[(buffer << (5 - bits)) & 31]
  return out
}

/** The binary key inside an ASCII-armored block. */
function dearmor(armored: string): Buffer {
  const body = armored
    .split('\n')
    .filter((line) => line && !line.startsWith('-----') && !line.includes(': ') && !line.startsWith('='))
    .join('')
  return Buffer.from(body, 'base64')
}

test('a new account gets an OpenPGP address key, signed by the account and published by WKD', async ({ browser }) => {
  test.slow()
  const account = newAccount('mailkeys', PASSWORD)
  const context = await browser.newContext({ acceptDownloads: true })
  await registerAccount(context, account)

  const page = await context.newPage()
  await page.goto(appUrl('account', '/settings/keys'))
  await expect(page.getByRole('heading', { name: 'Encryption keys', level: 1 })).toBeVisible({ timeout: 120_000 })
  const fingerprint = page.getByTestId('mail-key-fingerprint')
  await expect(fingerprint).toHaveCount(1, { timeout: 60_000 })
  await expect(page.getByText('Signed by your account (key list 1)')).toBeVisible()
  await expect(page.getByText('Primary', { exact: true })).toBeVisible()
  await expect(page.getByText('Curve25519 (Ed25519 and X25519)')).toBeVisible()
  const shown = (await fingerprint.textContent())!.replace(/\s/g, '').toLowerCase()
  expect(shown).toMatch(/^[0-9a-f]{40}$/)

  // Signing in again does not make a second key.
  await page.reload()
  await expect(page.getByText('Signed by your account (key list 1)')).toBeVisible({ timeout: 60_000 })
  await expect(page.getByTestId('mail-key-fingerprint')).toHaveCount(1)

  // The downloaded public key is the one WKD serves to the world.
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download public key' }).click(),
  ])
  expect(download.suggestedFilename()).toMatch(new RegExp(`^publickey\\.${account.username}@.+-${shown}\\.asc$`))
  const armored = await readFile((await download.path())!, 'utf8')
  expect(armored).toMatch(/^-----BEGIN PGP PUBLIC KEY BLOCK-----/)

  const wkd = await page.request.get(wkdUrl(account.username))
  expect(wkd.status()).toBe(200)
  expect(wkd.headers()['content-type']).toBe('application/octet-stream')
  expect(Buffer.compare(await wkd.body(), dearmor(armored))).toBe(0)
  // The advanced method (asked first by GnuPG and Proton when
  // openpgpkey.<domain> resolves) answers the same, for this server only.
  const serverName = download.suggestedFilename().split('@')[1].split('-')[0]
  const origin = (process.env.E2E_API_URL ?? appOrigin('account')).replace(/\/+$/, '')
  const advanced = await page.request.get(`${origin}/.well-known/openpgpkey/${serverName}/hu/${wkdHash(account.username)}?l=${account.username}`)
  expect(advanced.status()).toBe(200)
  expect(Buffer.compare(await advanced.body(), dearmor(armored))).toBe(0)
  expect((await page.request.get(`${origin}/.well-known/openpgpkey/${serverName}/policy`)).status()).toBe(200)
  expect((await page.request.get(`${origin}/.well-known/openpgpkey/example.org/policy`)).status()).toBe(404)
  // Another local part, or a hash that does not match it, finds nothing.
  expect((await page.request.get(wkdUrl('nobody'))).status()).toBe(404)
  expect((await page.request.get(wkdUrl(account.username, wkdHash('nobody')))).status()).toBe(404)
  await context.close()
})

test('an address key is exported locked, rotated, retired and imported back', async ({ browser }) => {
  test.slow()
  const account = newAccount('mailrotate', PASSWORD)
  const context = await browser.newContext({ acceptDownloads: true })
  await registerAccount(context, account)
  const page = await context.newPage()
  await page.goto(appUrl('account', '/settings/keys'))
  const fingerprints = page.getByTestId('mail-key-fingerprint')
  await expect(fingerprints).toHaveCount(1, { timeout: 120_000 })
  const first = (await fingerprints.first().textContent())!.replace(/\s/g, '').toLowerCase()

  // Export: a passphrase is required and confirmed; the file is locked.
  await page.getByRole('button', { name: 'More key actions' }).click()
  await page.getByRole('menuitem', { name: 'Export private key' }).click()
  const exportDialog = page.getByRole('dialog', { name: 'Export private key' })
  await exportDialog.getByLabel('Passphrase', { exact: true }).fill('short')
  await expect(exportDialog.getByText('At least 8 characters.')).toBeVisible()
  await exportDialog.getByLabel('Passphrase', { exact: true }).fill('export passphrase 1')
  await exportDialog.getByLabel('Passphrase again').fill('export passphrase 1')
  const [download] = await Promise.all([page.waitForEvent('download'), exportDialog.getByRole('button', { name: 'Export' }).click()])
  expect(download.suggestedFilename()).toMatch(new RegExp(`^privatekey\\.${account.username}@.+-${first}\\.asc$`))
  const exported = await readFile((await download.path())!, 'utf8')
  expect(exported).toMatch(/^-----BEGIN PGP PRIVATE KEY BLOCK-----/)

  // A new key takes over; the first stays to open older mail.
  await page.getByRole('button', { name: 'New key' }).click()
  await page.getByRole('dialog', { name: 'Create a new key?' }).getByRole('button', { name: 'Create key' }).click()
  await expect(fingerprints).toHaveCount(2, { timeout: 60_000 })
  await expect(page.getByText('Signed by your account (key list 2)')).toBeVisible()
  const firstRow = page.locator(`[data-fingerprint="${first}"]`)
  await expect(firstRow.getByText('Primary', { exact: true })).toHaveCount(0)

  // Retired: marked compromised after a confirmation.
  await firstRow.getByRole('button', { name: 'More key actions' }).click()
  await page.getByRole('menuitem', { name: 'Mark as compromised' }).click()
  await page.getByRole('alertdialog').getByRole('button', { name: 'Mark as compromised' }).click()
  await expect(page.getByText('Signed by your account (key list 3)')).toBeVisible({ timeout: 60_000 })
  await expect(firstRow.getByText('Compromised')).toBeVisible()

  // The exported file is the first key: importing it again is refused, and
  // a wrong passphrase is told apart.
  await page.getByRole('button', { name: 'Import key' }).click()
  const importDialog = page.getByRole('dialog', { name: 'Import a key' })
  await importDialog.getByLabel('Key file').setInputFiles({ name: 'key.asc', mimeType: 'application/pgp-keys', buffer: Buffer.from(exported) })
  await importDialog.getByLabel('Passphrase').fill('not the passphrase')
  await importDialog.getByRole('button', { name: 'Import' }).click()
  await expect(importDialog.getByText('The passphrase does not open this key file.')).toBeVisible({ timeout: 30_000 })
  await importDialog.getByLabel('Passphrase').fill('export passphrase 1')
  await importDialog.getByRole('button', { name: 'Import' }).click()
  await expect(importDialog.getByText('This key is already one of your keys.')).toBeVisible({ timeout: 30_000 })
  await context.close()
})
