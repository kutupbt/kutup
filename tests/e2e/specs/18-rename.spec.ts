import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

// Drive rename + editor-navbar inline rename (Google Docs style).
// The rename endpoint is E2EE-blind: the metadata blob is re-encrypted
// client-side and PUT to /files/:id. Backend only sees ciphertext.

test('drive: rename a note via the dropdown menu, name persists', async ({ context }) => {
    const page = await signInOrBootstrap(context)

    // Drive list might be in the root view; enter My Files to see notes.
    const myFiles = page.locator('text=My Files').first()
    if (await myFiles.count()) await myFiles.click().catch(() => {})
    await page.waitForTimeout(1_000)

    // Find any existing note row by ".md" suffix. The dev stack has 250+
    // notes already; we don't need to create one for this test.
    const row = page.locator('tr', { hasText: '.md' }).first()
    await expect(row).toBeVisible({ timeout: 10_000 })
    const oldNameRaw = (await row.locator('td').nth(1).textContent())?.trim() ?? ''
    const oldMatch = oldNameRaw.match(/[\w.-]+\.md/)
    const oldName = oldMatch?.[0] ?? ''
    expect(oldName.endsWith('.md'), `oldName looks like a .md filename (got "${oldNameRaw}")`).toBe(true)
    const newBase = `renamed-${Date.now()}`

    // Open the row's "..." dropdown menu and click Rename.
    await row.locator('button[aria-haspopup="menu"], button:has(svg)').last().click()
    await page.waitForTimeout(300)
    await page.locator('[role=menuitem]:has-text("Rename")').first().click()

    // Dialog opens with the basename (extension is locked + shown grayed).
    const input = page.locator('[role=dialog] input').first()
    await expect(input).toBeVisible()
    await input.fill(newBase)
    await page.locator('[role=dialog] button[type=submit]').first().click()
    await page.waitForTimeout(1_000)

    // Reload Drive and assert new name is present. Don't assert the old
    // name is gone — many other notes in the dev stack share substring
    // patterns (e.g. "n-tab-3-1.md" contains "1.md") so substring matches
    // give false positives.
    await page.reload()
    await page.waitForTimeout(2_000)
    await expect(page.locator(`tr:has-text("${newBase}.md")`).first()).toBeVisible()
})

test('editor: inline-rename a note from the navbar, name persists across reload', async ({ context }) => {
    const page = await signInOrBootstrap(context)
    const myFiles = page.locator('text=My Files').first()
    if (await myFiles.count()) await myFiles.click().catch(() => {})
    await page.waitForTimeout(1_000)

    // Open the most recent note (opens in a new tab via Drive's row click).
    const editorPromise = context.waitForEvent('page', { timeout: 30_000 })
    const noteRow = page.locator('tr', { hasText: '.md' }).first()
    await expect(noteRow).toBeVisible()
    await noteRow.locator('td').nth(1).dblclick()
    const editor = await editorPromise
    await editor.waitForLoadState('domcontentloaded')
    await editor.waitForTimeout(3_000)

    // Click the filename in the navbar to enter edit mode. The
    // EditableFilename renders the basename inside a <button> while
    // unfocused; clicking it swaps to an <input> showing only the base
    // (the .md is locked alongside, grayed out).
    const navBtn = editor.locator('header button[title$=".md"]').first()
    await expect(navBtn).toBeVisible()
    await navBtn.click()
    await editor.waitForTimeout(300)

    const newBase = `inline-${Date.now()}`
    const input = editor.locator('header input').first()
    await expect(input).toBeVisible()
    await input.fill(newBase)
    await editor.keyboard.press('Enter')
    await editor.waitForTimeout(2_000)

    // Reload the editor page; navbar should show the new name.
    await editor.reload()
    await editor.waitForTimeout(3_000)
    await expect(editor.locator(`header button[title="${newBase}.md"]`).first()).toBeVisible()
})
