import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Regression for pptx peer live cursor presence — wire-side only.
//
// The OO_CURSOR envelope wire is format-agnostic (PR #13); this test
// verifies pptx fits the same wire and that cursor frames flow A→B.
//
// The render side is OnlyOffice's design limitation (matched by CryptPad):
// slide's `drawingsUpdateForeignCursor` (slide/sdk-all.js:3012) only
// computes a visible position for the foreign cursor when the receiver
// is in an active text-edit context (`getTargetDocContent` non-null) —
// otherwise the cursor info is registered in `m_aForeignCursors` but
// never given a screen position, and the peer caret stays invisible.
// This is OO's intended UX: peer cursors only show up while you're
// actively co-editing the same shape. We cover the wire here and rely
// on manual hand-off + CryptPad parity for the render side.
test.describe('office pptx — peer live cursor presence (wire)', () => {
  test('cursor frames flow A→B', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(500)
    await page.locator('[role=menuitem]:has-text("Presentation")').first().click()
    const tabA = await tabAPromise
    await tabA.waitForLoadState('domcontentloaded')
    const fileUrl = tabA.url()

    const tabB = await context.newPage()
    await tabB.goto(fileUrl)
    await tabB.waitForLoadState('domcontentloaded')

    const aLogs = attachCollabLogs(tabA, 'A')
    const bLogs = attachCollabLogs(tabB, 'B')

    await tabA.waitForTimeout(30_000)

    // Tab A clicks into the title placeholder, enters edit mode, and
    // types — emits saveChanges + cursor frames.
    await tabA.bringToFront()
    await tabA.mouse.click(640, 280)
    await tabA.waitForTimeout(500)
    await tabA.mouse.dblclick(640, 280)
    await tabA.waitForTimeout(500)
    await tabA.keyboard.type('hello', { delay: 80 })
    await tabA.waitForTimeout(3_000)

    const outBefore = aLogs.filter((l) => l.includes('outbound cursor')).length
    const inBefore = bLogs.filter((l) => l.includes('applying remote cursor')).length

    // Caret motion within the textbox via keyboard — emits cursor frames.
    await tabA.keyboard.press('Home')
    await tabA.waitForTimeout(500)
    await tabA.keyboard.press('End')
    await tabA.waitForTimeout(2_000)

    const outAfter = aLogs.filter((l) => l.includes('outbound cursor')).length
    const inAfter = bLogs.filter((l) => l.includes('applying remote cursor')).length

    expect(outAfter - outBefore, 'tab A outbound cursor frames').toBeGreaterThan(0)
    expect(inAfter - inBefore, 'tab B applied remote cursor frames').toBeGreaterThan(0)
  })
})
