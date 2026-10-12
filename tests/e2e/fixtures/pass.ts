import { expect, type Page } from '@playwright/test'
import { appUrl } from './apps'

// Kutup Pass (docs/plans/pass.md): helpers the Pass specs share.

/** Opens Pass on its vault list. */
export async function openPass(page: Page): Promise<void> {
  await page.goto(appUrl('pass'))
  await expect(page.getByRole('heading', { name: 'Vaults', exact: true })).toBeVisible({ timeout: 120_000 })
}

/** Makes a vault from the vault list; it opens unlocked. Returns its page URL. */
export async function createVault(page: Page, name: string, password: string, remember = true): Promise<string> {
  await page.getByRole('button', { name: 'New vault' }).first().click()
  const dialog = page.getByRole('dialog', { name: 'New vault' })
  await dialog.getByLabel('Vault name').fill(name)
  await dialog.getByLabel('Vault password', { exact: true }).fill(password)
  await dialog.getByLabel('Repeat the vault password').fill(password)
  if (!remember) await dialog.getByRole('checkbox', { name: 'Unlock with my Kutup sign-in' }).click()
  await dialog.getByRole('button', { name: 'Create vault' }).click()
  await expect(page.getByRole('heading', { name, exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await expectSaved(page)
  return page.url()
}

/** Waits until the vault's edits are all in Drive. */
export async function expectSaved(page: Page): Promise<void> {
  await expect(page.getByRole('status').filter({ hasText: 'Saved' })).toBeVisible({ timeout: 60_000 })
}

export interface EntryFields {
  title: string
  userName?: string
  password?: string
  url?: string
  otp?: string
  notes?: string
}

async function fill(page: Page, fields: Partial<EntryFields>): Promise<void> {
  const dialog = page.getByRole('dialog')
  if (fields.title !== undefined) await dialog.getByLabel('Title', { exact: true }).fill(fields.title)
  if (fields.userName !== undefined) await dialog.getByLabel('User name', { exact: true }).fill(fields.userName)
  if (fields.password !== undefined) await dialog.getByLabel('Password', { exact: true }).fill(fields.password)
  if (fields.url !== undefined) await dialog.getByLabel('URL', { exact: true }).fill(fields.url)
  if (fields.otp !== undefined) await dialog.getByLabel('One-time code secret').fill(fields.otp)
  if (fields.notes !== undefined) await dialog.getByLabel('Notes', { exact: true }).fill(fields.notes)
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(dialog).toBeHidden()
}

export async function addEntry(page: Page, fields: EntryFields): Promise<void> {
  await page.getByRole('button', { name: 'New entry' }).click()
  await expect(page.getByRole('dialog', { name: 'New entry' })).toBeVisible()
  await fill(page, fields)
  await expect(page.getByRole('article', { name: fields.title })).toBeVisible()
}

export async function openEntry(page: Page, title: string): Promise<void> {
  await page.getByRole('list', { name: 'Entries' }).getByRole('button', { name: new RegExp(`^.?\\s*${title}`) }).click()
  await expect(page.getByRole('article', { name: title })).toBeVisible()
}

export async function editEntry(page: Page, title: string, fields: Partial<EntryFields>): Promise<void> {
  await openEntry(page, title)
  await page.getByRole('article', { name: title }).getByRole('button', { name: 'Edit' }).click()
  await expect(page.getByRole('dialog', { name: 'Edit entry' })).toBeVisible()
  await fill(page, fields)
}

/** A field's shown value in the open entry (user name, URL, plain fields). */
export function shownValue(page: Page, title: string, label: string) {
  return page.getByRole('article', { name: title }).locator('dt', { hasText: label }).locator('xpath=following-sibling::dd[1]')
}
