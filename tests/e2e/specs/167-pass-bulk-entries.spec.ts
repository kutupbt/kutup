import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { addEntry, createVault, expectSaved, openPass } from '../fixtures/pass'

const PASSWORD = 'Deneme123*PassBulkEntries'

const entries = (page: Page) => page.getByRole('list', { name: 'Entries' })
const row = (page: Page, title: string) => entries(page).getByRole('button', { name: new RegExp(`^.?\\s*${title}\\b`) })
const box = (page: Page, title: string) => entries(page).getByRole('checkbox', { name: `Select ${title}` })
const bar = (page: Page) => page.getByRole('toolbar', { name: 'Selected entries' })
const groups = (page: Page) => page.getByRole('navigation', { name: 'Groups' })

async function newGroup(page: Page, parent: string, name: string): Promise<void> {
  await page.getByRole('button', { name: `Actions for ${parent}` }).click()
  await page.getByRole('menuitem', { name: 'New group inside' }).click()
  const dialog = page.getByRole('dialog', { name: 'New group' })
  await dialog.getByLabel('Group name').fill(name)
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(groups(page).getByRole('button', { name, exact: true })).toBeVisible()
}

async function showGroup(page: Page, name: string): Promise<void> {
  await groups(page).getByRole('button', { name, exact: true }).click()
}

async function expectIn(page: Page, group: string, titles: string[]): Promise<void> {
  await showGroup(page, group)
  for (const title of titles) await expect(row(page, title)).toBeVisible({ timeout: 30_000 })
  await expect(entries(page).getByRole('listitem')).toHaveCount(titles.length)
}

// Several entries at once (docs/plans/pass-parity.md, "Bulk actions and the
// entry list"): checkboxes, Shift ranges, Ctrl toggles and select all; moved
// to a group, dragged onto one, recycled, restored each to where it was, and
// deleted for good from the bin, each as one edit.
test('pass: several entries are selected, moved, dragged, recycled, restored to their groups and deleted for good', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('pass167', PASSWORD))
  const page = await context.newPage()
  await page.goto(appUrl('pass'))
  await openPass(page)
  await createVault(page, 'Toplu', null)
  await newGroup(page, 'Toplu', 'İş')
  await newGroup(page, 'Toplu', 'Ev')
  await showGroup(page, 'All entries')
  for (const title of ['A1', 'A2', 'A3', 'A4']) await addEntry(page, { title, password: `p-${title}` })
  await expectSaved(page)
  await showGroup(page, 'All entries')

  // A checkbox, then Shift for the range; Ctrl-click takes one out.
  await box(page, 'A1').click()
  await expect(bar(page)).toContainText('1 selected')
  await box(page, 'A3').click({ modifiers: ['Shift'] })
  await expect(bar(page)).toContainText('3 selected')
  await row(page, 'A2').click({ modifiers: ['ControlOrMeta'] })
  await expect(bar(page)).toContainText('2 selected')
  await expect(box(page, 'A2')).not.toBeChecked()

  // Moved to a group together.
  await bar(page).getByRole('button', { name: 'Move to group', exact: true }).click()
  await page.getByRole('menuitem', { name: 'İş' }).click()
  await expect(page.getByText('2 entries moved to İş')).toBeVisible()
  await expect(bar(page)).toBeHidden()
  await expectIn(page, 'İş', ['A1', 'A3'])

  // Dragged onto a group.
  await showGroup(page, 'All entries')
  await row(page, 'A2').dragTo(groups(page).getByRole('button', { name: 'Ev', exact: true }))
  await expect(page.getByText('1 entry moved to Ev')).toBeVisible()
  await expectIn(page, 'Ev', ['A2'])

  // Everything shown (Ctrl+A) into the recycle bin, asked first.
  await showGroup(page, 'All entries')
  await row(page, 'A4').focus()
  await page.keyboard.press('ControlOrMeta+a')
  await expect(bar(page)).toContainText('4 selected')
  await bar(page).getByRole('button', { name: 'Move to recycle bin', exact: true }).click()
  const recycle = page.getByRole('alertdialog', { name: 'Move 4 entries to the recycle bin?' })
  await recycle.getByRole('button', { name: 'Move to recycle bin' }).click()
  await expect(page.getByText('4 entries moved to the recycle bin')).toBeVisible()
  await expectIn(page, 'Recycle bin', ['A1', 'A2', 'A3', 'A4'])

  // Restored, each to the group it was in.
  await row(page, 'A1').focus()
  await page.keyboard.press('ControlOrMeta+a')
  await bar(page).getByRole('button', { name: 'Restore', exact: true }).click()
  await expect(page.getByText('4 entries restored to where they were')).toBeVisible()
  await expectIn(page, 'İş', ['A1', 'A3'])
  await expectIn(page, 'Ev', ['A2'])
  await showGroup(page, 'All entries')
  await expect(row(page, 'A4')).toBeVisible()

  // Deleted for good from the bin, with its warning; never by a drag.
  await row(page, 'A4').dragTo(groups(page).getByRole('button', { name: 'Recycle bin', exact: true }))
  await expect(page.getByText('1 entry moved to the recycle bin')).toBeVisible()
  await showGroup(page, 'Recycle bin')
  await box(page, 'A4').click()
  await bar(page).getByRole('button', { name: 'Delete for good', exact: true }).click()
  const forGood = page.getByRole('alertdialog', { name: 'Delete 1 entry for good?' })
  await expect(forGood).toContainText("This can't be undone.")
  await forGood.getByRole('button', { name: 'Delete for good' }).click()
  await expect(page.getByText('1 entry deleted for good')).toBeVisible()
  await expect(page.getByText('The recycle bin is empty.')).toBeVisible()
  await expectSaved(page)

  // Saved as shown: after a reload, everything where it was put.
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Toplu', exact: true, level: 1 })).toBeVisible({ timeout: 60_000 })
  await expectIn(page, 'İş', ['A1', 'A3'])
  await expectIn(page, 'Ev', ['A2'])
  await context.close()
})
