import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

// Regression for commit be712d9.
//
// Bug: TextCollabEditor's cold-start `ytext.insert(0, initialContent)` ran on
// every open when no S3 snapshot existed, and the WS replay of the prior
// session's seed CRDT-merged with the new local insert — duplicating the
// "# Untitled" heading on each reopen. Fix: defer the seed until onHello
// confirms `headSeq === 0`.
test.describe('note initial-seed is not duplicated', () => {
  test('opening the same fresh note three times keeps content stable', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    // Create a new note.
    const editor1Promise = context.waitForEvent('page', { timeout: 30_000 })
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(500)
    await page.locator('[role=menuitem]:has-text("Note")').first().click()
    await page.waitForTimeout(500)
    await page.locator('button:has-text("Create")').last().click()

    const editor1 = await editor1Promise
    await editor1.waitForLoadState('domcontentloaded')
    const fileUrl = editor1.url()
    // Wait long enough for WS connect + onHello to seed Y.Text.
    await editor1.waitForTimeout(6_000)

    const text1 = await editor1.evaluate(() => {
      const el = document.querySelector('.cm-content')
      return el ? (el as HTMLElement).innerText : null
    })
    await editor1.close()
    expect((text1 ?? '').trim()).toBe('# Untitled')

    // Reopen — the bug duplicated the heading here.
    const editor2 = await context.newPage()
    await editor2.goto(fileUrl)
    await editor2.waitForLoadState('domcontentloaded')
    await editor2.waitForTimeout(6_000)
    const text2 = await editor2.evaluate(() => {
      const el = document.querySelector('.cm-content')
      return el ? (el as HTMLElement).innerText : null
    })
    await editor2.close()
    expect((text2 ?? '').trim()).toBe('# Untitled')

    // One more open to make sure subsequent reopens stay stable.
    const editor3 = await context.newPage()
    await editor3.goto(fileUrl)
    await editor3.waitForLoadState('domcontentloaded')
    await editor3.waitForTimeout(6_000)
    const text3 = await editor3.evaluate(() => {
      const el = document.querySelector('.cm-content')
      return el ? (el as HTMLElement).innerText : null
    })
    expect((text3 ?? '').trim()).toBe('# Untitled')
  })
})
