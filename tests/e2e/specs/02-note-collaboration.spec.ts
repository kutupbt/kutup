import { expect, test, type Page } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { createNote, noteText, openNote, typeAtEnd } from '../fixtures/drive'

const PASSWORD = 'Deneme123*NoteCollabPassword'

/** How many times the note's seed (its first line when made) appears in `text`. */
function seedCount(text: string, seed: string): number {
  return text.split(seed).length - 1
}

async function freshNote(browser: import('@playwright/test').Browser, prefix: string) {
  const context = await browser.newContext()
  await registerAccount(context, newAccount(prefix, PASSWORD))
  const drive = await openDrive(context)
  await createNote(drive)
  const url = drive.url()
  // The seed heading's words, without its `#` (drawn or not).
  const seed = (await noteText(drive)).split('\n')[0].replace(/^#+\s*/, '').trim()
  expect(seed).not.toBe('')
  await drive.close()
  return { context, url, seed }
}

test('a fresh note keeps its seed once, however often it is reopened', async ({ browser }) => {
  const { context, url, seed } = await freshNote(browser, 'noteseed')
  for (let open = 1; open <= 3; open++) {
    const page = await openNote(context, url)
    // Give a late duplicate seed time to arrive before judging.
    await page.waitForTimeout(2_000)
    expect(seedCount(await noteText(page), seed), `open ${open}`).toBe(1)
    await page.close()
  }
  await context.close()
})

for (let run = 1; run <= 3; run++) {
  test(`two tabs opening a note at once both sync (run ${run})`, async ({ browser }) => {
    const { context, url, seed } = await freshNote(browser, 'noterace')
    const [a, b] = await Promise.all([context.newPage(), context.newPage()])
    await Promise.all([a.goto(url), b.goto(url)])
    for (const page of [a, b]) await expect(page.getByRole('status').filter({ hasText: 'Live' })).toBeVisible({ timeout: 60_000 })
    await typeAtEnd(a, ' edit-from-A')
    await typeAtEnd(b, ' edit-from-B')
    for (const page of [a, b]) {
      await expect.poll(() => noteText(page), { timeout: 30_000 }).toContain('edit-from-A')
      await expect.poll(() => noteText(page), { timeout: 30_000 }).toContain('edit-from-B')
      expect(seedCount(await noteText(page), seed)).toBe(1)
    }
    await context.close()
  })
}

for (const tabs of [3, 5]) {
  test(`${tabs} tabs see each other's edits`, async ({ browser }) => {
    test.slow()
    const { context, url, seed } = await freshNote(browser, `notetabs${tabs}`)
    const pages: Page[] = []
    for (let i = 0; i < tabs; i++) pages.push(await openNote(context, url))
    const tags = pages.map((_, i) => `<tab${i}>`)
    for (const [i, page] of pages.entries()) await typeAtEnd(page, ` ${tags[i]}`)
    for (const [i, page] of pages.entries()) {
      for (const tag of tags) await expect.poll(() => noteText(page), { timeout: 30_000, message: `tab ${i} has ${tag}` }).toContain(tag)
      expect(seedCount(await noteText(page), seed), `tab ${i} seed`).toBe(1)
    }
    await context.close()
  })
}
