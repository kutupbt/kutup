import { expect, test, type Browser } from '@playwright/test'
import { appUrl, newAccount, openDrive, registerAccount, signIn } from '../fixtures/apps'
import { item, openItem } from '../fixtures/drive'
import {
  appliedCursors,
  appliedRemote,
  createOffice,
  editorFrame,
  freshOfficeFile,
  officeReady,
  openOffice,
  outboundChanges,
  outboundCursors,
  write,
  type OfficeKind,
  type OfficeTab,
} from '../fixtures/office'

const PASSWORD = 'Deneme123*OfficeCollabPassword'

/**
 * `from` moves its cursor and `to` draws `from`'s caret in its document,
 * with a real size. The tabs of one browser share a device: each tab is its
 * own participant all the same (the room names it by its tab).
 */
async function caretShown(from: OfficeTab, to: OfficeTab) {
  const sent = outboundCursors(from)
  const applied = appliedCursors(to)
  await from.page.keyboard.press('Home')
  await from.page.keyboard.press('End')
  await expect.poll(() => outboundCursors(from), { timeout: 30_000 }).toBeGreaterThan(sent)
  await expect.poll(() => appliedCursors(to), { timeout: 30_000 }).toBeGreaterThan(applied)
  const frame = await editorFrame(to.page)
  await expect
    .poll(
      () =>
        frame.evaluate(() => {
          const w = window as unknown as { editor?: any; editorDoc?: any }
          const targets = (w.editor || w.editorDoc)?.WordControl?.m_oDrawingDocument?.CollaborativeTargets ?? []
          const box = targets[0]?.HtmlElement?.getBoundingClientRect?.()
          return box ? box.width > 0 && box.height > 0 && document.contains(targets[0].HtmlElement) : false
        }),
      { timeout: 30_000, message: "the peer's caret is drawn" },
    )
    .toBe(true)
}

async function pair(browser: import('@playwright/test').Browser, kind: OfficeKind) {
  const { context, url } = await freshOfficeFile(browser, kind, PASSWORD)
  const a = await openOffice(context, url)
  const b = await openOffice(context, url)
  return { context, url, a, b }
}

/** Waits until `to` applied a change from `from` after `from` sent one. */
async function flows(from: OfficeTab, to: OfficeTab, sentBefore: number, appliedBefore: number) {
  await expect.poll(() => outboundChanges(from), { timeout: 30_000, message: 'changes sent' }).toBeGreaterThan(sentBefore)
  await expect.poll(() => appliedRemote(to), { timeout: 30_000, message: 'changes applied by the peer' }).toBeGreaterThan(appliedBefore)
}

for (const kind of ['Document', 'Spreadsheet', 'Presentation'] as const) {
  test(`${kind}: edits flow from A to B, then from B to A`, async ({ browser }) => {
    test.slow()
    const { context, a, b } = await pair(browser, kind)
    await write(a, kind, 'first')
    if (kind === 'Spreadsheet') await a.page.keyboard.press('Enter')
    await flows(a, b, 0, 0)

    const sentByB = outboundChanges(b)
    const appliedByA = appliedRemote(a)
    // Slides: the subtitle, so B does not type into A's locked title.
    const at = kind === 'Presentation' ? { x: 760, y: 440, open: 'dblclick' as const } : kind === 'Spreadsheet' ? { x: 290, y: 237 } : undefined
    await write(b, kind, 'second', at)
    if (kind === 'Spreadsheet') await b.page.keyboard.press('Enter')
    await flows(b, a, sentByB, appliedByA)
    await context.close()
  })
}

test('Spreadsheet: concurrent edits in different cells reach both tabs', async ({ browser }) => {
  test.slow()
  const { context, a, b } = await pair(browser, 'Spreadsheet')
  await a.page.bringToFront()
  await a.page.mouse.click(162, 237)
  await b.page.bringToFront()
  await b.page.mouse.click(290, 237)
  await Promise.all([a.page.keyboard.type('alpha', { delay: 60 }), b.page.keyboard.type('beta', { delay: 60 })])
  await Promise.all([a.page.keyboard.press('Enter'), b.page.keyboard.press('Enter')])
  for (const [from, to] of [
    [a, b],
    [b, a],
  ] as const) {
    await expect.poll(() => outboundChanges(from), { timeout: 30_000 }).toBeGreaterThan(0)
    await expect.poll(() => appliedRemote(to), { timeout: 30_000 }).toBeGreaterThan(0)
  }
  await context.close()
})

for (let run = 1; run <= 2; run++) {
  test(`Spreadsheet: two tabs opening at once both sync (run ${run})`, async ({ browser }) => {
    test.slow()
    const { context, url } = await freshOfficeFile(browser, 'Spreadsheet', PASSWORD)
    const [a, b] = await Promise.all([openOffice(context, url), openOffice(context, url)])
    await write(a, 'Spreadsheet', 'alpha')
    await a.page.keyboard.press('Enter')
    await flows(a, b, 0, 0)
    await context.close()
  })
}

for (const kind of ['Document', 'Presentation'] as const) {
  test(`${kind}: the cursor moves are shown to the peer`, async ({ browser }) => {
    test.slow()
    const { context, a, b } = await pair(browser, kind)
    await write(a, kind, 'hello')
    const sent = outboundCursors(a)
    const applied = appliedCursors(b)
    await a.page.keyboard.press('Home')
    await a.page.keyboard.press('End')
    await expect.poll(() => outboundCursors(a), { timeout: 30_000 }).toBeGreaterThan(sent)
    await expect.poll(() => appliedCursors(b), { timeout: 30_000 }).toBeGreaterThan(applied)

    if (kind === 'Document') {
      // Each tab draws the other's caret: two tabs of one account.
      await caretShown(a, b)
      await caretShown(b, a)
    }
    await context.close()
  })
}

// Two people: Alice shares a document from its editor and Bob opens it; each
// draws the other's caret.
test('Document: two accounts see each other\'s caret', async ({ browser }: { browser: Browser }) => {
  test.slow()
  const alice = newAccount('caretalice', PASSWORD)
  const bob = newAccount('caretbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)

  const drive = await openDrive(contextA)
  const logs: string[] = []
  drive.on('console', (line) => {
    if (line.text().includes('[kutup-bridge]')) logs.push(line.text())
  })
  const url = await createOffice(drive, 'Document')
  await officeReady({ page: drive, logs })
  await drive.getByRole('button', { name: 'Share', exact: true }).click()
  const dialog = drive.getByRole('dialog')
  await dialog.getByLabel('Kutup address').fill(bob.address)
  await dialog.getByRole('combobox', { name: 'What they can do' }).click()
  await drive.getByRole('option', { name: 'Can edit', exact: true }).click()
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect(drive.getByText(`Shared with ${bob.username}`, { exact: false }).first()).toBeVisible({ timeout: 30_000 })
  await drive.close()

  const a = await openOffice(contextA, url)
  // Bob opens it from Shared with me: the URL Alice has goes through her
  // folder.
  const bobPage = await contextB.newPage()
  const bobLogs: string[] = []
  bobPage.on('console', (line) => {
    if (line.text().includes('[kutup-bridge]')) bobLogs.push(line.text())
  })
  await bobPage.goto(appUrl('drive', '/shared'))
  await expect(item(bobPage, 'Untitled document.docx')).toBeVisible({ timeout: 60_000 })
  await openItem(bobPage, 'Untitled document.docx')
  const b = { page: bobPage, logs: bobLogs }
  await officeReady(b)
  await write(a, 'Document', 'hello')
  await caretShown(a, b)
  await caretShown(b, a)
  await contextA.close()
  await contextB.close()
})

// One account on two devices (two browsers, each signed in), the first with
// two tabs: device ids are per account and the tabs of a browser share its
// device, so every tab is told apart by its account, device and tab.
test('Document: two tabs of one device and a second device of the account see each other\'s caret', async ({ browser }: { browser: Browser }) => {
  test.slow()
  const account = newAccount('caretdevices', PASSWORD)
  const first = await browser.newContext()
  await registerAccount(first, account)
  const drive = await openDrive(first)
  const url = await createOffice(drive, 'Document')
  await drive.close()
  const second = await browser.newContext()
  await signIn(second, account)

  const a = await openOffice(first, url)
  const b = await openOffice(first, url)
  const c = await openOffice(second, url)
  await write(a, 'Document', 'hello')
  await caretShown(a, b)
  await caretShown(b, a)
  await caretShown(a, c)
  await caretShown(c, a)
  await caretShown(b, c)
  await first.close()
  await second.close()
})
