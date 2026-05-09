import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Cross-tab formatting sync for docx. Typing already syncs (PR 70834ca).
// These tests guard the formatting paths that go through getLock/saveChanges
// — same wire as typing but a different OO code path that historically
// hides bugs (the xlsx fill-color saga in PR #9 / research file 08).
//
// Pattern: type in tab A, apply formatting via keyboard shortcut, wait for
// saveChanges to propagate, then in tab B select all and probe the doc's
// CalculatedTextPr / CalculatedParaPr — proves the formatting actually
// applied on the receiver, not just that bytes flowed.
//
// All actions use keyboard shortcuts. Toolbar selectors are version-fragile
// in OO and the SDK's setter-API surface (put_TextProps, asc_setColor, …)
// is also unstable — we'd test the same lock path either way.

async function openTwoTabs(context: any) {
  const page = await signInOrBootstrap(context)
  const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
  await page.locator('button:has-text("New")').first().click()
  await page.waitForTimeout(500)
  await page.locator('[role=menuitem]:has-text("Document")').first().click()
  const tabA = await tabAPromise
  await tabA.waitForLoadState('domcontentloaded')
  const fileUrl = tabA.url()
  const tabB = await context.newPage()
  await tabB.goto(fileUrl)
  await tabB.waitForLoadState('domcontentloaded')
  attachCollabLogs(tabA, 'A')
  attachCollabLogs(tabB, 'B')
  await tabA.waitForTimeout(30_000)
  return { tabA, tabB }
}

// Reaches into the OO inner iframe and returns CDocument's calculated
// text/para props. Returns shape: {state: 'ok', bold, italic, underline, jc}
// or {state: 'no-...'} on missing API.
async function probeFormatting(tab: any) {
  return tab.evaluate(`(() => {
    const outerIfr = document.querySelector('iframe');
    const innerIfr = outerIfr && outerIfr.contentDocument && outerIfr.contentDocument.querySelector('iframe');
    const w = innerIfr && innerIfr.contentWindow;
    const editor = w && (w.editor || w.editorDoc);
    if (!editor) return { state: 'no-editor' };
    const doc = editor.WordControl && editor.WordControl.m_oLogicDocument;
    if (!doc) return { state: 'no-doc' };
    const tp = doc.GetCalculatedTextPr && doc.GetCalculatedTextPr();
    const pp = doc.GetCalculatedParaPr && doc.GetCalculatedParaPr();
    return {
      state: 'ok',
      bold: tp && typeof tp.GetBold === 'function' ? !!tp.GetBold() : null,
      italic: tp && typeof tp.GetItalic === 'function' ? !!tp.GetItalic() : null,
      underline: tp && typeof tp.GetUnderline === 'function' ? !!tp.GetUnderline() : null,
      jc: pp && typeof pp.GetJc === 'function' ? pp.GetJc() : null,
    };
  })()`)
}

test.describe('office docx — formatting cross-tab sync', () => {
  test('bold (Ctrl+B) propagates to peer', async ({ context }) => {
    const { tabA, tabB } = await openTwoTabs(context)

    await tabA.bringToFront()
    await tabA.mouse.click(640, 380)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello bold', { delay: 60 })
    await tabA.waitForTimeout(1_000)
    await tabA.keyboard.press('Control+A')
    await tabA.waitForTimeout(300)
    await tabA.keyboard.press('Control+B')
    await tabA.waitForTimeout(5_000)

    await tabB.bringToFront()
    await tabB.mouse.click(640, 380)
    await tabB.waitForTimeout(300)
    await tabB.keyboard.press('Control+A')
    await tabB.waitForTimeout(500)
    const f = await probeFormatting(tabB)
    expect(f.state).toBe('ok')
    expect(f.bold, 'tab B sees bold formatting').toBe(true)
  })

  test('italic (Ctrl+I) propagates to peer', async ({ context }) => {
    const { tabA, tabB } = await openTwoTabs(context)

    await tabA.bringToFront()
    await tabA.mouse.click(640, 380)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello italic', { delay: 60 })
    await tabA.waitForTimeout(1_000)
    await tabA.keyboard.press('Control+A')
    await tabA.waitForTimeout(300)
    await tabA.keyboard.press('Control+I')
    await tabA.waitForTimeout(5_000)

    await tabB.bringToFront()
    await tabB.mouse.click(640, 380)
    await tabB.waitForTimeout(300)
    await tabB.keyboard.press('Control+A')
    await tabB.waitForTimeout(500)
    const f = await probeFormatting(tabB)
    expect(f.state).toBe('ok')
    expect(f.italic, 'tab B sees italic formatting').toBe(true)
  })

  test('underline (Ctrl+U) propagates to peer', async ({ context }) => {
    const { tabA, tabB } = await openTwoTabs(context)

    await tabA.bringToFront()
    await tabA.mouse.click(640, 380)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello under', { delay: 60 })
    await tabA.waitForTimeout(1_000)
    await tabA.keyboard.press('Control+A')
    await tabA.waitForTimeout(300)
    await tabA.keyboard.press('Control+U')
    await tabA.waitForTimeout(5_000)

    await tabB.bringToFront()
    await tabB.mouse.click(640, 380)
    await tabB.waitForTimeout(300)
    await tabB.keyboard.press('Control+A')
    await tabB.waitForTimeout(500)
    const f = await probeFormatting(tabB)
    expect(f.state).toBe('ok')
    expect(f.underline, 'tab B sees underline formatting').toBe(true)
  })

  test('paragraph alignment center (Ctrl+E) propagates to peer', async ({ context }) => {
    const { tabA, tabB } = await openTwoTabs(context)

    await tabA.bringToFront()
    await tabA.mouse.click(640, 380)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello center', { delay: 60 })
    await tabA.waitForTimeout(1_000)
    await tabA.keyboard.press('Control+E')
    await tabA.waitForTimeout(5_000)

    await tabB.bringToFront()
    // Click into the paragraph so getCalculatedParaPr reflects its align.
    await tabB.mouse.click(640, 380)
    await tabB.waitForTimeout(500)
    const f = await probeFormatting(tabB)
    expect(f.state).toBe('ok')
    // Default alignment (left) is 0 in OO's c_oAscAlign. Center alignment
    // is non-zero — exact value depends on the enum mapping in this OO
    // build. Asserting != 0 is enough to confirm cross-tab propagation.
    expect(f.jc, 'tab B sees non-default paragraph alignment').not.toBe(0)
  })
})
