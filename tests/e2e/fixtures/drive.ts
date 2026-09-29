import { expect, type Page } from '@playwright/test'
import { appUrl } from './apps'

/** Drive's primary navigation: My files, Shared, Trash, … */
export async function openSection(page: Page, name: 'My files' | 'Shared with me' | 'Shared by me' | 'Trash') {
  await page.getByRole('link', { name, exact: true }).first().click()
}

/** The item called `name` in the current listing (list or grid view). */
export function item(page: Page, name: string) {
  return page.getByRole('button', { name: `Actions for ${name}`, exact: true })
}

/** Runs one of an item's actions from its menu (Rename, Move to trash, …). */
export async function itemAction(page: Page, name: string, action: string) {
  await item(page, name).click()
  await page.getByRole('menuitem', { name: action, exact: true }).click()
}

/** Opens an item: a folder shows its listing, a file its editor or viewer. */
export async function openItem(page: Page, name: string) {
  await page.getByText(name, { exact: true }).first().dblclick()
}

async function createFromMenu(page: Page, entry: string) {
  await page.getByRole('button', { name: 'New' }).first().click()
  await page.getByRole('menuitem', { name: entry, exact: true }).click()
}

/**
 * Creates a note in the current folder and opens it; returns its name as
 * the editor shows it.
 */
export async function createNote(page: Page): Promise<string> {
  await createFromMenu(page, 'Note')
  await page.waitForURL(/\/file\//, { timeout: 60_000 })
  await expect(page.locator('.cm-content')).toBeVisible({ timeout: 60_000 })
  const title = page.getByRole('button', { name: /\.md$/ }).first()
  await expect(title).toBeVisible()
  return (await title.textContent())!.trim()
}

/** Leaves the editor for the folder it was opened from. */
export async function backFromEditor(page: Page) {
  await page.getByRole('link', { name: /^Back to / }).click()
  await expect(page.getByRole('group', { name: 'View' })).toBeVisible({ timeout: 60_000 })
}

export async function createFolder(page: Page, name: string) {
  await createFromMenu(page, 'Folder')
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Name').fill(name)
  await dialog.getByRole('button', { name: 'Create', exact: true }).click()
  await expect(dialog).toBeHidden()
  await expect(item(page, name)).toBeVisible({ timeout: 30_000 })
}

/** Renames through the item's menu and waits for the new name. */
export async function renameItem(page: Page, name: string, to: string) {
  await itemAction(page, name, 'Rename')
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Name').fill(to)
  await dialog.getByRole('button', { name: 'Rename', exact: true }).click()
  await expect(dialog).toBeHidden({ timeout: 15_000 })
  await expect(item(page, to)).toBeVisible({ timeout: 30_000 })
}

export function driveUrl(path = '/') {
  return appUrl('drive', path)
}
