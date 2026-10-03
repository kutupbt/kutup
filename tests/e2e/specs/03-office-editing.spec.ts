import { expect, test, type Browser } from '@playwright/test'
import { editorCanvases, freshOfficeFile, openOffice, outboundChanges, reloadOffice, write, type OfficeKind } from '../fixtures/office'

const PASSWORD = 'Deneme123*OfficeEditPassword'

async function freshFile(browser: Browser, kind: OfficeKind) {
  const { context, url } = await freshOfficeFile(browser, kind, PASSWORD)
  return { context, url, tab: await openOffice(context, url) }
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
