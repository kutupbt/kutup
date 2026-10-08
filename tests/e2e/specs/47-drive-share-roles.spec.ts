import { expect, test, type Page } from '@playwright/test'
import { appUrl, newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { createFolder, createNote, item, itemAction, noteLive, openItem } from '../fixtures/drive'

const PASSWORD = 'Deneme123*ShareRolesPassword'

/** The role menu on someone's row in a share dialog. */
function roleMenu(page: Page) {
  return page.getByRole('dialog').getByRole('button', { name: /^What .+ can do$/ })
}

async function chooseRole(page: Page, role: string) {
  await roleMenu(page).click()
  await page.getByRole('menuitem', { name: role, exact: true }).click()
}

test('the owner changes what someone may do with a file without sharing it again', async ({ browser }) => {
  test.slow()
  const alice = newAccount('rolealice', PASSWORD)
  const bob = newAccount('rolebob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)

  const a = await openDrive(contextA)
  const note = await createNote(a)
  await noteLive(a)
  const noteUrl = a.url()

  // Shared to view: the role is chosen beside the address.
  await a.getByRole('button', { name: 'Share', exact: true }).click()
  const dialog = a.getByRole('dialog')
  await dialog.getByLabel('Email or Kutup address').fill(bob.email)
  await expect(dialog.getByTestId('file-share-role')).toHaveText('Can view')
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(roleMenu(a)).toHaveText('Can view', { timeout: 30_000 })

  const b = await contextB.newPage()
  await b.goto(appUrl('drive', '/shared'))
  await expect(item(b, note)).toBeVisible({ timeout: 60_000 })
  await openItem(b, note)
  const bobEditor = b.locator('.cm-content')
  await expect(bobEditor).toHaveAttribute('contenteditable', 'false', { timeout: 60_000 })

  // Made an editor from the row: one share request, nobody removed.
  const shared = a.waitForResponse((r) => r.request().method() === 'POST' && /\/api\/files\/[^/]+\/share$/.test(new URL(r.url()).pathname))
  await chooseRole(a, 'Can edit')
  expect((await shared).status()).toBe(204)
  await expect(a.getByText(/can now edit it/).first()).toBeVisible({ timeout: 30_000 })
  await expect(roleMenu(a)).toHaveText('Can edit')

  await b.reload()
  await expect(bobEditor).toHaveAttribute('contenteditable', 'true', { timeout: 60_000 })

  // The change is the server's, not this dialog's.
  await a.goto(noteUrl)
  await noteLive(a)
  await a.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(roleMenu(a)).toHaveText('Can edit', { timeout: 30_000 })

  // And back to viewer.
  await chooseRole(a, 'Can view')
  await expect(a.getByText(/can now only view it/).first()).toBeVisible({ timeout: 30_000 })
  await b.reload()
  await expect(bobEditor).toHaveAttribute('contenteditable', 'false', { timeout: 60_000 })

  await contextA.close()
  await contextB.close()
})

test('a folder manager changes what someone may do in a folder without sharing it again', async ({ browser }) => {
  test.slow()
  const tag = Date.now()
  const alice = newAccount('folderrolealice', PASSWORD)
  const bob = newAccount('folderrolebob', PASSWORD)
  const contextA = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(await browser.newContext(), bob)

  const a = await openDrive(contextA)
  const folder = `roles-${tag}`
  await createFolder(a, folder)
  await itemAction(a, folder, 'Share')
  let dialog = a.getByRole('dialog')
  await dialog.getByLabel('Email or Kutup address').fill(bob.email)
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(dialog).toBeHidden({ timeout: 30_000 })

  await itemAction(a, folder, 'Share')
  dialog = a.getByRole('dialog')
  await expect(roleMenu(a)).toHaveText('Can view', { timeout: 30_000 })
  const shared = a.waitForResponse((r) => r.request().method() === 'POST' && /\/api\/collections\/[^/]+\/share$/.test(new URL(r.url()).pathname))
  await chooseRole(a, 'Can add and edit')
  expect((await shared).status()).toBe(201)
  await expect(roleMenu(a)).toHaveText('Can add and edit', { timeout: 30_000 })

  // Deleting what they added is offered only to someone who can add.
  await roleMenu(a).click()
  await a.getByRole('menuitemcheckbox', { name: 'Can delete files they added' }).click()
  await expect(a.getByText(/access is updated/).first()).toBeVisible({ timeout: 30_000 })

  await a.reload()
  await itemAction(a, folder, 'Share')
  await expect(roleMenu(a)).toHaveText('Can add and edit', { timeout: 30_000 })
  await roleMenu(a).click()
  await expect(a.getByRole('menuitemcheckbox', { name: 'Can delete files they added' })).toHaveAttribute('aria-checked', 'true')
  await a.keyboard.press('Escape')

  // Back to viewer: deleting goes with it.
  await chooseRole(a, 'Can view')
  await expect(roleMenu(a)).toHaveText('Can view', { timeout: 30_000 })
  await roleMenu(a).click()
  const deleting = a.getByRole('menuitemcheckbox', { name: 'Can delete files they added' })
  await expect(deleting).toHaveAttribute('aria-checked', 'false')
  await expect(deleting).toBeDisabled()

  await contextA.close()
})
