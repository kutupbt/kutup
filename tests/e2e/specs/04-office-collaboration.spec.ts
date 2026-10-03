import { expect, test } from '@playwright/test'
import {
  appliedCursors,
  appliedRemote,
  editorFrame,
  freshOfficeFile,
  openOffice,
  outboundChanges,
  outboundCursors,
  write,
  type OfficeKind,
  type OfficeTab,
} from '../fixtures/office'

const PASSWORD = 'Deneme123*OfficeCollabPassword'

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
      // The peer's caret is drawn in B's document, with a real size.
      const frame = await editorFrame(b.page)
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
    await context.close()
  })
}
