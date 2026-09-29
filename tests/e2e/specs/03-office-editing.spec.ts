import { expect, test, type Browser } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { createOffice, editorCanvases, openOffice, outboundChanges, reloadOffice, typeAt, type OfficeKind, type OfficeTab } from '../fixtures/office'

const PASSWORD = 'Deneme123*OfficeEditPassword'

/** Where typing lands in a fresh file of each kind (a 1280×720 window). */
const WRITE_AT: Record<OfficeKind, { x: number; y: number; open?: 'dblclick' }> = {
  Document: { x: 640, y: 300 },
  Spreadsheet: { x: 162, y: 237 },
  Presentation: { x: 760, y: 330, open: 'dblclick' },
}

async function freshFile(browser: Browser, kind: OfficeKind) {
  const context = await browser.newContext()
  await registerAccount(context, newAccount(`off${kind.slice(0, 3).toLowerCase()}`, PASSWORD))
  const drive = await openDrive(context)
  const url = await createOffice(drive, kind)
  await drive.close()
  return { context, url, tab: await openOffice(context, url) }
}

async function write(tab: OfficeTab, kind: OfficeKind, text: string) {
  const at = WRITE_AT[kind]
  if (at.open === 'dblclick') {
    await tab.page.bringToFront()
    await tab.page.mouse.dblclick(at.x, at.y)
    await tab.page.keyboard.type(text, { delay: 60 })
  } else {
    await typeAt(tab, at.x, at.y, text)
  }
}

for (const kind of ['Document', 'Spreadsheet', 'Presentation'] as const) {
  test(`${kind}: typing sends encrypted changes`, async ({ browser }) => {
    test.slow()
    const { context, tab } = await freshFile(browser, kind)
    await write(tab, kind, 'hello')
    if (kind === 'Spreadsheet') await tab.page.keyboard.press('Enter')
    await expect.poll(() => outboundChanges(tab), { timeout: 30_000 }).toBeGreaterThan(0)

    if (kind === 'Document') {
      // A new paragraph is still editable (the lock-block regression).
      const before = outboundChanges(tab)
      await tab.page.keyboard.press('Enter')
      await tab.page.keyboard.type('second paragraph', { delay: 60 })
      await expect.poll(() => outboundChanges(tab), { timeout: 30_000 }).toBeGreaterThan(before)
    }
    await context.close()
  })

  test(`${kind}: reloading keeps the editor loaded`, async ({ browser }) => {
    test.slow()
    const { context, tab } = await freshFile(browser, kind)
    expect(await editorCanvases(tab.page)).toBeGreaterThan(0)
    await reloadOffice(tab)
    expect(await editorCanvases(tab.page)).toBeGreaterThan(0)
    await context.close()
  })
}
