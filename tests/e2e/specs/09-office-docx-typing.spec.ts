import { test, expect } from '@playwright/test'
import { signInOrBootstrap, attachCollabLogs } from '../fixtures/auth'

// Regression: in docx, typing one letter works, then Enter, then typing
// stops emitting input until the user clicks elsewhere — and even then it's
// flaky. Cause: inner.html's getLock handler indexed obj.block[0]; for xlsx
// obj.block is an array of cell-range objects (correct), but for docx it's
// a string (paragraph block GUID), so [0] picks the first character of the
// GUID. The mangled lock id never matched the requested block, so OO refused
// to grant — input was queued but never accepted.
test('docx accepts input after Enter (lock-block shape regression)', async ({ context }) => {
  const page = await signInOrBootstrap(context)

  const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
  await page.locator('button:has-text("New")').first().click()
  await page.waitForTimeout(500)
  await page.locator('[role=menuitem]:has-text("Document")').first().click()
  const tabA = await tabAPromise
  await tabA.waitForLoadState('domcontentloaded')

  const aLogs = attachCollabLogs(tabA, 'A')

  // OO docx bootstrap budget — same as the xlsx tests.
  await tabA.waitForTimeout(30_000)

  // Click into the document body. The OnlyOffice doc canvas sits inside a
  // nested iframe; clicking somewhere in the middle of the visible area
  // lands the caret in a paragraph.
  await tabA.bringToFront()
  await tabA.mouse.click(640, 380)
  await tabA.waitForTimeout(500)

  // Phase 1: type 'a' a few times in the first paragraph — works pre-fix.
  await tabA.keyboard.type('aaaa', { delay: 80 })
  await tabA.waitForTimeout(2_000)

  const phase1Out = aLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length

  // Phase 2 — the user's repro: Enter (new paragraph block) then more 'a's.
  // Pre-fix this paragraph never emits saveChanges because OO never grants
  // the new-block lock.
  await tabA.keyboard.press('Enter')
  await tabA.waitForTimeout(500)
  await tabA.keyboard.type('bbbb', { delay: 80 })
  await tabA.waitForTimeout(3_000)

  const phase2Out = aLogs.filter((l) => l.includes('outbound saveChanges') && /raw=([1-9]\d*)/.test(l)).length
  const newSaveChanges = phase2Out - phase1Out

  expect(phase1Out, 'phase 1 (first paragraph) outbound saveChanges').toBeGreaterThan(0)
  expect(newSaveChanges, 'phase 2 (post-Enter paragraph) outbound saveChanges').toBeGreaterThan(0)
})
