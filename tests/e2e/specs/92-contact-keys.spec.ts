import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Contacts' keys for outside addresses, as Proton's "Edit email settings"
// (docs/plans/contact-keys.md): with nothing found online, keys are
// uploaded; an address keeps several, in order, the first used for
// sending; Encrypt, Sign and the PGP scheme are set per address and kept.

const PASSWORD = 'Deneme123*ContactKeysPassword'

/** A GnuPG key file for `address` (Ed25519 and Curve25519, a year), armored. */
function gpgKey(dir: string, address: string): string {
  const home = mkdtempSync(path.join(dir, 'gpg-'))
  const gpg = (...args: string[]) => execFileSync('gpg', ['--homedir', home, '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', ...args])
  gpg('--quick-gen-key', `Dave <${address}>`, 'ed25519', 'cert,sign', '1y')
  const fingerprint = /^fpr:+([0-9A-F]{40}):/m.exec(execFileSync('gpg', ['--homedir', home, '--with-colons', '--list-keys', address]).toString())![1]
  gpg('--quick-add-key', fingerprint, 'cv25519', 'encr', '1y')
  const file = path.join(dir, `${fingerprint}.asc`)
  writeFileSync(file, gpg('--armor', '--export', address))
  return file
}

async function openSettings(page: Page, address: string) {
  const person = page.getByRole('article', { name: 'Dave Outside' })
  await person.getByRole('button', { name: 'Email settings' }).click()
  const dialog = page.getByRole('dialog', { name: 'Email settings' })
  await expect(dialog.getByText(address)).toBeVisible()
  await expect(dialog.getByText('Looking for keys online…')).toHaveCount(0, { timeout: 60_000 })
  return dialog
}

test('an outside address keeps several keys in order, with Encrypt, Sign and scheme of its own', async ({ browser }) => {
  test.slow()
  const dir = mkdtempSync(path.join(tmpdir(), 'kutup-contact-keys-'))
  try {
    const tag = Date.now().toString(36)
    const address = `dave-${tag}@example.invalid`
    const first = gpgKey(dir, address)
    const second = gpgKey(dir, address)
    const context = await browser.newContext()
    await registerAccount(context, newAccount('ckeys', PASSWORD))
    const page = await context.newPage()
    await page.goto(appUrl('contacts'))
    await expect(page.getByText('No contacts yet')).toBeVisible({ timeout: 120_000 })
    await page.getByRole('button', { name: 'New contact' }).first().click()
    const editor = page.getByRole('dialog', { name: 'New contact' })
    await editor.getByLabel('First name').fill('Dave')
    await editor.getByLabel('Last name').fill('Outside')
    await editor.getByLabel('Email address').fill(address)
    await editor.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByText('Contact added')).toBeVisible({ timeout: 30_000 })

    // Nothing found online: Proton's set-up hint, and upload.
    let dialog = await openSettings(page, address)
    await expect(dialog.getByText(/No key was found for this address online/)).toBeVisible()
    await expect(dialog.getByRole('checkbox', { name: /Encrypt/ })).toBeDisabled()
    await dialog.locator('input[type="file"]').setInputFiles(first)
    const rows = dialog.locator('tbody tr')
    await expect(rows).toHaveCount(1, { timeout: 30_000 })
    await expect(rows.first().getByText('Trusted')).toBeVisible()
    await expect(rows.first().getByText('Used for sending')).toBeVisible()
    await expect(rows.first().getByText('ECC (Curve25519)')).toBeVisible({ timeout: 30_000 })
    // A second key goes first, used for sending; the first stays trusted.
    await dialog.locator('input[type="file"]').setInputFiles(second)
    await expect(rows).toHaveCount(2, { timeout: 30_000 })
    const secondFingerprint = path.basename(second, '.asc').toLowerCase()
    const firstFingerprint = path.basename(first, '.asc').toLowerCase()
    await expect(dialog.locator(`[data-fingerprint="${secondFingerprint}"]`).getByText('Used for sending')).toBeVisible()
    await expect(dialog.locator(`[data-fingerprint="${firstFingerprint}"]`).getByText('Trusted')).toBeVisible()
    // Back to the first for sending.
    await dialog.getByRole('button', { name: `Actions for key ${firstFingerprint.slice(-8).toUpperCase()}` }).click()
    await page.getByRole('menuitem', { name: 'Use for sending' }).click()
    await expect(dialog.locator(`[data-fingerprint="${firstFingerprint}"]`).getByText('Used for sending')).toBeVisible()
    // Encrypting signs; with Encrypt off, Sign and the scheme are the address's own.
    await expect(dialog.getByRole('combobox', { name: 'Sign' })).toBeDisabled()
    await dialog.getByRole('checkbox', { name: /Encrypt/ }).click()
    await dialog.getByRole('combobox', { name: 'Sign' }).click()
    await page.getByRole('option', { name: "Don't sign" }).click()
    await dialog.getByRole('combobox', { name: 'PGP scheme' }).click()
    await page.getByRole('option', { name: 'Inline' }).click()
    await dialog.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByText('Email settings saved.')).toBeVisible({ timeout: 30_000 })
    await expect(page.getByRole('article', { name: 'Dave Outside' }).getByText('Not encrypted')).toBeVisible()

    // Kept, after a reload: two keys in order, the preferences.
    await page.reload()
    dialog = await openSettings(page, address)
    await expect(rows).toHaveCount(2, { timeout: 30_000 })
    await expect(dialog.getByRole('checkbox', { name: /Encrypt/ })).not.toBeChecked()
    await expect(dialog.getByRole('combobox', { name: 'Sign' })).toHaveText("Don't sign")
    await expect(dialog.getByRole('combobox', { name: 'PGP scheme' })).toHaveText('Inline')
    // Encrypt on again: the first key is still the one used for sending.
    await dialog.getByRole('checkbox', { name: /Encrypt/ }).click()
    await expect(dialog.locator(`[data-fingerprint="${firstFingerprint}"]`).getByText('Used for sending')).toBeVisible()
    // Remove the second (an uploaded key).
    await dialog.getByRole('button', { name: `Actions for key ${secondFingerprint.slice(-8).toUpperCase()}` }).click()
    await page.getByRole('menuitem', { name: 'Remove' }).click()
    await expect(rows).toHaveCount(1)
    await dialog.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByText('Email settings saved.')).toBeVisible({ timeout: 30_000 })
    await expect(page.getByRole('article', { name: 'Dave Outside' }).getByText('1 trusted key')).toBeVisible()
    await context.close()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
