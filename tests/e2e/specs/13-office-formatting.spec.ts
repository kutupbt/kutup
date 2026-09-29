import { expect, test, type Browser } from '@playwright/test'
import { editorFrame, freshOfficeFile, openOffice, write, type OfficeTab } from '../fixtures/office'

const PASSWORD = 'Deneme123*OfficeFormatPassword'

async function pair(browser: Browser, kind: 'Document' | 'Spreadsheet') {
  const { context, url } = await freshOfficeFile(browser, kind, PASSWORD)
  return { context, a: await openOffice(context, url), b: await openOffice(context, url) }
}

/** The text formatting at the selection in a document, from ONLYOFFICE's model. */
async function documentFormatting(tab: OfficeTab) {
  const frame = await editorFrame(tab.page)
  return frame.evaluate(() => {
    const w = window as unknown as { editor?: any; editorDoc?: any }
    const doc = (w.editor || w.editorDoc)?.WordControl?.m_oLogicDocument
    if (!doc) return null
    const text = doc.GetCalculatedTextPr?.()
    const paragraph = doc.GetCalculatedParaPr?.()
    return {
      bold: !!text?.GetBold?.(),
      italic: !!text?.GetItalic?.(),
      underline: !!text?.GetUnderline?.(),
      alignment: paragraph?.GetJc?.() ?? null,
    }
  })
}

const DOCUMENT_CASES = [
  { name: 'bold', keys: ['Control+A', 'Control+B'], expect: { bold: true } },
  { name: 'italic', keys: ['Control+A', 'Control+I'], expect: { italic: true } },
  { name: 'underline', keys: ['Control+A', 'Control+U'], expect: { underline: true } },
] as const

for (const format of DOCUMENT_CASES) {
  test(`Document: ${format.name} reaches the peer`, async ({ browser }) => {
    test.slow()
    const { context, a, b } = await pair(browser, 'Document')
    await write(a, 'Document', `hello ${format.name}`)
    for (const key of format.keys) await a.page.keyboard.press(key)
    await b.page.bringToFront()
    await b.page.mouse.click(640, 300)
    await expect
      .poll(
        async () => {
          await b.page.keyboard.press('Control+A')
          return documentFormatting(b)
        },
        { timeout: 30_000 },
      )
      .toMatchObject(format.expect)
    await context.close()
  })
}

test('Document: centring a paragraph reaches the peer', async ({ browser }) => {
  test.slow()
  const { context, a, b } = await pair(browser, 'Document')
  await write(a, 'Document', 'hello centre')
  await a.page.keyboard.press('Control+E')
  await b.page.bringToFront()
  await b.page.mouse.click(640, 300)
  await expect.poll(async () => (await documentFormatting(b))?.alignment, { timeout: 30_000 }).not.toBe(0)
  await context.close()
})

/** The font of the active cell in a sheet, from ONLYOFFICE's model. */
async function cellFont(tab: OfficeTab) {
  const frame = await editorFrame(tab.page)
  return frame.evaluate(() => {
    const w = window as unknown as { editor?: any; editorCell?: any }
    const wb = (w.editor || w.editorCell)?.wb
    const ws = wb?.model?.getActiveWs?.()
    const active = ws?.selectionRange?.activeCell
    const cell = active && (ws.getCell3?.(active.row, active.col) ?? ws.getCell?.(active.row, active.col))
    const font = cell?.getFont?.()
    if (!font) return null
    return { bold: !!font.getBold?.(), italic: !!font.getItalic?.(), underline: !!font.getUnderline?.() }
  })
}

/** Sets a font attribute on the active cell through ONLYOFFICE's API. */
async function setCellFont(tab: OfficeTab, attribute: 'b' | 'i' | 'u') {
  const frame = await editorFrame(tab.page)
  return frame.evaluate((attr) => {
    const w = window as unknown as { editor?: any; editorCell?: any; Asc?: any }
    const wb = (w.editor || w.editorCell)?.wb
    if (typeof wb?.setFontAttributes !== 'function') return false
    wb.setFontAttributes(attr, attr === 'u' ? w.Asc?.EUnderline?.underlineSingle : true)
    return true
  }, attribute)
}

for (const [attribute, name] of [
  ['b', 'bold'],
  ['i', 'italic'],
  ['u', 'underline'],
] as const) {
  test(`Spreadsheet: cell ${name} reaches the peer`, async ({ browser }) => {
    test.slow()
    const { context, a, b } = await pair(browser, 'Spreadsheet')
    await write(a, 'Spreadsheet', 'hello')
    await a.page.keyboard.press('Enter')
    await a.page.mouse.click(162, 237)
    expect(await setCellFont(a, attribute)).toBe(true)
    await expect.poll(async () => (await cellFont(a))?.[name], { timeout: 15_000 }).toBe(true)
    await b.page.bringToFront()
    await b.page.mouse.click(162, 237)
    await expect.poll(async () => (await cellFont(b))?.[name], { timeout: 30_000 }).toBe(true)
    await context.close()
  })
}
