import { expect, test } from '@playwright/test'
import { apiUrl, appUrl, newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { createOffice, officeReady } from '../fixtures/office'
import { backFromEditor, createFolder, createNote, item, itemAction, noteLive, noteText, openItem, typeAtEnd } from '../fixtures/drive'

const PASSWORD = 'Deneme123*TwoUserCollabPassword'

test('a note in a shared folder is edited together by two people', async ({ browser }) => {
  test.slow()
  const tag = Date.now()
  const alice = newAccount('collabalice', PASSWORD)
  const bob = newAccount('collabbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)

  const a = await openDrive(contextA)
  const folder = `shared-${tag}`
  await createFolder(a, folder)
  await openItem(a, folder)
  await expect(a.getByRole('navigation', { name: 'Breadcrumb' })).toContainText(folder, { timeout: 30_000 })
  const note = await createNote(a)
  const noteUrl = a.url()
  await noteLive(a)
  await typeAtEnd(a, ` SEED-${tag}`)
  await backFromEditor(a)
  await a.getByRole('link', { name: 'My files', exact: true }).first().click()
  await expect(item(a, folder)).toBeVisible({ timeout: 30_000 })

  // Share within the server: sealed to Bob's key, never through federation.
  const federated: string[] = []
  let localShare = 0
  a.on('response', (response) => {
    const path = new URL(response.url()).pathname
    if (/\/federated-shares$/.test(path)) federated.push(path)
    if (/^\/api\/collections\/[^/]+\/share$/.test(path) && response.request().method() === 'POST') localShare = response.status()
  })
  await itemAction(a, folder, 'Share')
  const dialog = a.getByRole('dialog')
  await dialog.getByLabel('Email or Kutup address').fill(bob.email)
  await dialog.getByLabel('Can add and edit files').check()
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect.poll(() => localShare, { timeout: 30_000 }).toBe(201)
  expect(federated).toEqual([])
  await a.keyboard.press('Escape')

  // The same with Bob's Kutup address on this server (user@server), which
  // looks like an email address but is not one. It is still a share within
  // the server.
  const settings = await a.request.get(apiUrl('/auth/settings'))
  const serverName = ((await settings.json()) as { chat: { serverName: string } }).chat.serverName
  const second = `by-address-${tag}`
  await createFolder(a, second)
  localShare = 0
  await itemAction(a, second, 'Share')
  await dialog.getByLabel('Email or Kutup address').fill(`${bob.username}@${serverName}`)
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect.poll(() => localShare, { timeout: 30_000 }).toBe(201)
  expect(federated).toEqual([])
  await a.keyboard.press('Escape')

  // An address here that nobody has is "no account", not a failed share.
  await itemAction(a, second, 'Share')
  await dialog.getByLabel('Email or Kutup address').fill(`nobody-${tag}@${serverName}`)
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(dialog.getByRole('alert')).toContainText(/no account|not found|No one/i, { timeout: 30_000 })
  await a.keyboard.press('Escape')

  // Bob finds it under Shared with me and opens the note.
  const b = await contextB.newPage()
  await b.goto(appUrl('drive', '/shared'))
  await expect.poll(
    async () => {
      if ((await item(b, folder).count()) > 0) return true
      await b.reload()
      return false
    },
    { timeout: 60_000, intervals: [1_000, 2_000] },
  ).toBe(true)
  await openItem(b, folder)
  await expect(item(b, note)).toBeVisible({ timeout: 60_000 })
  await openItem(b, note)
  await noteLive(b)
  await expect.poll(() => noteText(b), { timeout: 30_000 }).toContain(`SEED-${tag}`)

  const noteA = await contextA.newPage()
  await noteA.goto(noteUrl)
  await noteLive(noteA)
  await typeAtEnd(noteA, ` FROM-A-${tag}`)
  await expect.poll(() => noteText(b), { timeout: 30_000 }).toContain(`FROM-A-${tag}`)
  await typeAtEnd(b, ` FROM-B-${tag}`)
  await expect.poll(() => noteText(noteA), { timeout: 30_000 }).toContain(`FROM-B-${tag}`)
  await contextA.close()
  await contextB.close()
})

// Sharing a file does not need a trip back to the folder: the file's own
// view has a Share button, for its owner and for editors allowed to share.
test('a file is shared from its own view', async ({ browser }) => {
  test.slow()
  const alice = newAccount('viewalice', PASSWORD)
  const bob = newAccount('viewbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)

  const a = await openDrive(contextA)
  const note = await createNote(a)
  await noteLive(a)

  await a.getByRole('button', { name: 'Share', exact: true }).click()
  const dialog = a.getByRole('dialog').filter({ hasText: "They get this file's own key" })
  await expect(dialog.getByRole('heading').first()).toContainText(note)
  await dialog.getByLabel('Email or Kutup address').fill(bob.email)
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(a.getByText(`Shared with ${bob.username}`, { exact: false }).first()).toBeVisible({ timeout: 30_000 })
  // Still in the editor.
  await expect(a.locator('.cm-content')).toBeVisible()

  // Bob has the file, and no Share button of his own: a viewer cannot share.
  const b = await contextB.newPage()
  await b.goto(appUrl('drive', '/shared'))
  await expect(item(b, note)).toBeVisible({ timeout: 60_000 })
  await openItem(b, note)
  await expect(b.locator('.cm-content')).toBeVisible({ timeout: 60_000 })
  await expect(b.getByRole('button', { name: 'Share', exact: true })).toHaveCount(0)

  // The same button in the office editor.
  await a.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
  await backFromEditor(a)
  const logs: string[] = []
  a.on('console', (line) => {
    if (line.text().includes('[kutup-bridge]')) logs.push(line.text())
  })
  await createOffice(a, 'Document')
  await officeReady({ page: a, logs })
  await a.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(dialog.getByRole('heading').first()).toContainText('.docx')
  await dialog.getByLabel('Email or Kutup address').fill(bob.email)
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(a.getByText(`Shared with ${bob.username}`, { exact: false }).first()).toBeVisible({ timeout: 30_000 })

  await contextA.close()
  await contextB.close()
})
