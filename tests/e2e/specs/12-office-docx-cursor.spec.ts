import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Regression for docx peer live cursor presence.
//
// Wire flow (format-agnostic, shipped with PR #13 for xlsx):
//   tab A: OO emits 'cursor' on selection change → bridge wraps as
//     {type:'cursor', messages:[{cursor, time, user, useridoriginal}]}
//     → KIND.OO_CURSOR envelope → relay → tab B
//   tab B: bridge unwraps → sendToOO(payload) → OO's onCursor handler →
//     CDocument.prototype.Update_ForeignCursor → caret rendered.
//
// Failure mode this guards against: docx render-side blockage. xlsx works
// because the cell SDK redraws constantly and drains the foreign-cursor
// paint queue automatically; word's queue (CollaborativeTargetsUpdateTasks)
// only drains on a paint timer that idles between edits, so a peer caret
// would never visualise without our explicit Collaborative_TargetsUpdate
// kick in inner.html's oo-remote-cursor handler.
test.describe('office docx — peer live cursor presence', () => {
  test('peer caret renders in tab B with non-zero bounding box', async ({ context }) => {
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

    const aLogs = attachCollabLogs(tabA, 'A')
    const bLogs = attachCollabLogs(tabB, 'B')

    await tabA.waitForTimeout(30_000)

    // Type so both tabs share an aligned doc tree (Run-IDs converged via
    // saveChanges). Without this, CDocument.Update_ForeignCursor's
    // TableId.Get_ById guard could bail.
    await tabA.bringToFront()
    await tabA.mouse.click(640, 380)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello', { delay: 80 })
    await tabA.waitForTimeout(3_000)

    // Snapshot wire counts before triggering selection-only events.
    const outBefore = aLogs.filter((l) => l.includes('outbound cursor')).length
    const inBefore = bLogs.filter((l) => l.includes('applying remote cursor')).length

    // Distinct selection changes in A — OO emits cursor for each.
    await tabA.mouse.click(900, 500)
    await tabA.waitForTimeout(500)
    await tabA.mouse.click(640, 380)
    await tabA.waitForTimeout(2_000)

    const outAfter = aLogs.filter((l) => l.includes('outbound cursor')).length
    const inAfter = bLogs.filter((l) => l.includes('applying remote cursor')).length

    // Wire-side asserts.
    expect(outAfter - outBefore, 'tab A outbound cursor frames after selection').toBeGreaterThan(0)
    expect(inAfter - inBefore, 'tab B applied remote cursor frames').toBeGreaterThan(0)

    // Render-side assert: the peer's caret element exists in tab B's
    // OO iframe with non-zero dimensions and a non-default color.
    await tabB.bringToFront()
    const peerCaret = await tabB.evaluate(() => {
      const outerIfr = document.querySelector('iframe') as HTMLIFrameElement | null
      const innerIfr = outerIfr?.contentDocument?.querySelector('iframe') as HTMLIFrameElement | null
      const w = innerIfr?.contentWindow as any
      if (!w) return { state: 'no-inner-window' }
      const editor = w.editor || w.editorDoc
      if (!editor) return { state: 'no-editor' }
      const dd = editor.WordControl?.m_oDrawingDocument
      const targets = dd?.CollaborativeTargets || []
      if (!targets.length) return { state: 'no-targets' }
      const t = targets[0]
      const el = t.HtmlElement
      const r = el?.getBoundingClientRect?.()
      return {
        state: 'ok',
        targetCount: targets.length,
        hasElement: !!el,
        elementInDom: !!(el && (innerIfr!.contentDocument!.contains(el))),
        boxWidth: r?.width ?? 0,
        boxHeight: r?.height ?? 0,
        color: t.Color ? `${t.Color.r},${t.Color.g},${t.Color.b}` : null,
      }
    })

    expect(peerCaret.state, 'OO state probe').toBe('ok')
    expect(peerCaret.targetCount, 'CollaborativeTargets count').toBeGreaterThan(0)
    expect(peerCaret.hasElement, 'caret HtmlElement exists').toBe(true)
    expect(peerCaret.elementInDom, 'caret in DOM').toBe(true)
    expect(peerCaret.boxWidth, 'caret has non-zero width').toBeGreaterThan(0)
    expect(peerCaret.boxHeight, 'caret has non-zero height').toBeGreaterThan(0)
  })
})
