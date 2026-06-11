import { test, expect, type Page } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

// Trash lifecycle (migration 019 + /api/trash endpoints):
//   delete → row leaves My Files → appears decrypted in Trash →
//   restore → back in My Files → delete again → Delete forever → gone.
// Folder deletes cascade the whole subtree as ONE trash entry; restoring
// the folder brings its files back with it.
//
// The trash list decrypts names client-side (collection key → file key →
// metadata), so asserting the plaintext name in the Trash view also covers
// the E2EE unwrap path of GET /api/trash.

async function enterMyFiles(page: Page) {
    const myFiles = page.locator('text=My Files').first()
    if (await myFiles.count()) await myFiles.click().catch(() => {})
    await page.waitForTimeout(1_000)
}

/** Sidebar navigation — works for both My Files and Trash entries. */
async function goToSidebar(page: Page, label: string) {
    await page.locator(`nav button:has-text("${label}"), aside button:has-text("${label}"), button:has-text("${label}")`).first().click()
    await page.waitForTimeout(1_000)
}

/** Create a note via New → Note with a chosen filename; closes the editor tab. */
async function createNote(page: Page, name: string) {
    const editorPromise = page.context().waitForEvent('page', { timeout: 30_000 })
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(300)
    await page.locator('[role=menuitem]:has-text("Note")').first().click()
    await page.waitForTimeout(300)
    const input = page.locator('[role=dialog] input').first()
    await expect(input).toBeVisible()
    await input.fill(name)
    await page.locator('[role=dialog] button:has-text("Create")').last().click()
    const editor = await editorPromise
    await editor.waitForLoadState('domcontentloaded')
    await editor.waitForTimeout(2_000)
    await editor.close()
    await page.waitForTimeout(500)
}

/** Open a Drive row's ⋯ menu and click "Move to Trash", then confirm. */
async function moveRowToTrash(page: Page, rowText: string) {
    const row = page.locator('tr', { hasText: rowText }).first()
    await expect(row).toBeVisible()
    await row.locator('button[aria-haspopup="menu"], button:has(svg)').last().click()
    await page.waitForTimeout(300)
    await page.locator('[role=menuitem]:has-text("Move to Trash")').first().click()
    await page.waitForTimeout(300)
    await page.locator('[role=alertdialog] button:has-text("Move to Trash")').click()
    await page.waitForTimeout(1_000)
}

test('file: delete → restore from trash → delete forever', async ({ context }) => {
    const page = await signInOrBootstrap(context)
    await enterMyFiles(page)

    const name = `trash-file-${Date.now()}.md`
    await createNote(page, name)
    await expect(page.locator('tr', { hasText: name }).first()).toBeVisible()

    // Move to trash → row leaves My Files.
    await moveRowToTrash(page, name)
    await expect(page.locator('tr', { hasText: name })).toHaveCount(0)

    // Trash shows the item with its DECRYPTED name (covers the client-side
    // collection-key → file-key → metadata unwrap of GET /api/trash).
    await goToSidebar(page, 'Trash')
    const trashRow = page.locator('[data-testid=trash-row]', { hasText: name }).first()
    await expect(trashRow).toBeVisible()

    // Restore → row leaves the trash, file is back in My Files.
    await trashRow.locator('button:has-text("Restore")').click()
    await expect(page.locator('[data-testid=trash-row]', { hasText: name })).toHaveCount(0)
    await goToSidebar(page, 'My Files')
    await enterMyFiles(page)
    await expect(page.locator('tr', { hasText: name }).first()).toBeVisible()

    // Delete again, then permanently.
    await moveRowToTrash(page, name)
    await goToSidebar(page, 'Trash')
    const trashRow2 = page.locator('[data-testid=trash-row]', { hasText: name }).first()
    await expect(trashRow2).toBeVisible()
    await trashRow2.locator('button:has-text("Delete forever")').click()
    await page.waitForTimeout(300)
    await page.locator('[role=alertdialog] button:has-text("Delete forever")').click()
    await expect(page.locator('[data-testid=trash-row]', { hasText: name })).toHaveCount(0)

    // Survives a reload (it really is gone server-side, not just locally).
    await page.reload()
    await page.waitForTimeout(2_000)
    await goToSidebar(page, 'Trash')
    await expect(page.locator('[data-testid=trash-row]', { hasText: name })).toHaveCount(0)
})

test('folder: cascade delete → single trash entry → restore brings the file back', async ({ context }) => {
    const page = await signInOrBootstrap(context)
    await enterMyFiles(page)

    // Create a folder and a note inside it.
    const folderName = `trash-folder-${Date.now()}`
    const fileName = `inside-${Date.now()}.md`
    await page.locator('button:has-text("New")').first().click()
    await page.waitForTimeout(300)
    await page.locator('[role=menuitem]:has-text("Folder")').first().click()
    await page.waitForTimeout(300)
    const input = page.locator('[role=dialog] input').first()
    await input.fill(folderName)
    await page.locator('[role=dialog] button[type=submit], [role=dialog] button:has-text("Create")').last().click()
    await page.waitForTimeout(1_000)

    await page.locator(`text=${folderName}`).first().click()
    await page.waitForTimeout(1_000)
    await createNote(page, fileName)
    await expect(page.locator('tr', { hasText: fileName }).first()).toBeVisible()

    // Delete the folder from inside isn't the flow — go up and delete its tile.
    await goToSidebar(page, 'My Files')
    await enterMyFiles(page)
    const tile = page.locator(`[role=button]:has-text("${folderName}"), div:has-text("${folderName}")`).filter({ has: page.locator('button[aria-haspopup="menu"]') }).last()
    await tile.locator('button[aria-haspopup="menu"]').last().click()
    await page.waitForTimeout(300)
    await page.locator('[role=menuitem]:has-text("Move to Trash")').first().click()
    await page.waitForTimeout(300)
    await page.locator('[role=alertdialog] button:has-text("Move to Trash")').click()
    await page.waitForTimeout(1_000)

    // One folder entry in the trash; the file inside has NO separate entry.
    await goToSidebar(page, 'Trash')
    await expect(page.locator('[data-testid=trash-row]', { hasText: folderName }).first()).toBeVisible()
    await expect(page.locator('[data-testid=trash-row]', { hasText: fileName })).toHaveCount(0)

    // Restore the folder → the file inside is back too.
    await page.locator('[data-testid=trash-row]', { hasText: folderName }).first()
        .locator('button:has-text("Restore")').click()
    await page.waitForTimeout(1_000)
    await goToSidebar(page, 'My Files')
    await enterMyFiles(page)
    await page.locator(`text=${folderName}`).first().click()
    await page.waitForTimeout(1_500)
    await expect(page.locator('tr', { hasText: fileName }).first()).toBeVisible()
})
