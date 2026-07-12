import { test } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'
import { mkdirSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// Curated Drive screenshot for the README hero. NOT a regression test —
// re-running this overwrites docs/screenshots/01-drive.png so it stays
// current with the live UI.
//
// Distinct from screenshots.spec.ts (which produces 02-06 — editor +
// settings shots). Splitting responsibilities means:
//   - This spec nukes Drive contents first, then creates a curated set.
//     Re-runs are idempotent.
//   - screenshots.spec.ts creates editor-content files which need to
//     persist through the rest of its sequence; nuking would invalidate.
//
// Sized to 1280x720 (Playwright's default desktop viewport), light theme,
// fullPage: false so the height matches 02-06 when stacked in README.

const SCREENSHOTS_DIR = join(__dirname, '..', '..', '..', 'docs', 'screenshots')

// Folder names kept short so the Drive UI's fixed-width folder cards
// don't truncate them ("Meeting notes" became "Meetin..." in v1).
const FOLDER_NAMES = ['Specs', 'Designs', 'Notes']

// Ordered oldest-to-newest so the LAST one created shows at the top
// under Modified DESC. Note creation prompts for a name (we type
// directly); office + whiteboard files auto-suffix "Untitled.<ext>"
// (Drive.tsx:551-558) and we rename them via the UI rename dialog
// after creation.
const FILE_NAMES = [
  { menuItem: 'Note',          autoExt: 'md',         name: 'Project plan.md' },
  { menuItem: 'Spreadsheet',   autoExt: 'xlsx',       name: 'Q1 budget.xlsx' },
  { menuItem: 'Document',      autoExt: 'docx',       name: 'Roadmap.docx' },
  { menuItem: 'Whiteboard',    autoExt: 'excalidraw', name: 'Architecture sketch.excalidraw' },
  { menuItem: 'Presentation',  autoExt: 'pptx',       name: 'Pitch deck.pptx' },
] as const

test.describe('README curated drive screenshot', () => {
  test.setTimeout(300_000)

  test('nuke + curated set + 01-drive.png', async ({ context }) => {
    mkdirSync(SCREENSHOTS_DIR, { recursive: true })

    const drive = await signInOrBootstrap(context)

    async function forceLight(p: typeof drive) {
      await p.evaluate(() => {
        localStorage.setItem('kutup-theme', 'light')
        document.documentElement.classList.remove('dark')
        document.documentElement.classList.add('light')
      })
    }
    await forceLight(drive)
    await drive.reload()
    await drive.waitForLoadState('domcontentloaded')
    await drive.waitForTimeout(2_000)

    // ---- Nuke pass ----
    // Auth via the refresh-token cookie pattern (mirrors
    // 24-whiteboard-image-quota.spec.ts:22-39). The refresh cookie is
    // httpOnly + auto-attached; we use it to mint a bearer token for
    // the listing + DELETE calls.
    await drive.evaluate(async () => {
      const refreshRes = await fetch('/api/auth/refresh', {
        method: 'POST', credentials: 'include',
      })
      if (!refreshRes.ok) throw new Error('refresh failed: ' + refreshRes.status)
      const { accessToken } = await refreshRes.json()
      const auth = { Authorization: 'Bearer ' + accessToken }

      // 1. Delete every top-level collection. ON DELETE CASCADE on
      //    files.collection_id wipes their files. Some may 403/404 if
      //    they're not deletable (e.g. an auto-created root); ignore
      //    those — step 2 catches their files.
      const cols = await fetch('/api/collections/', { headers: auth })
        .then((r) => r.json()) as Array<{ id: string; parentCollectionId?: string | null }>
      for (const c of cols) {
        if (c.parentCollectionId == null) {
          await fetch('/api/collections/' + c.id, { method: 'DELETE', headers: auth })
        }
      }

      // 2. Re-list collections + delete files in any survivors.
      //    (Defensive: if the auto-created root resisted deletion in
      //    step 1, we still need to empty its files.)
      const survivors = await fetch('/api/collections/', { headers: auth })
        .then((r) => r.json()) as Array<{ id: string }>
      for (const c of survivors) {
        const files = await fetch('/api/collections/' + c.id + '/files', { headers: auth })
          .then((r) => r.json()) as Array<{ id: string }>
        for (const f of files) {
          await fetch('/api/files/' + f.id, { method: 'DELETE', headers: auth })
        }
      }

      // 3. The deletes above soft-delete into the trash (quota stays
      //    held); empty it so re-runs don't accumulate held quota.
      await fetch('/api/trash', { method: 'DELETE', headers: auth })
    })

    // Reload to a clean state. The app may have re-created an empty
    // "My Files" root or just shown an empty list.
    await drive.reload()
    await drive.waitForLoadState('domcontentloaded')
    await drive.waitForTimeout(2_000)

    // ---- Curate: 3 folders ----
    // Created first so under Modified DESC they sort to the bottom of
    // the list, leaving the more-recently-created files at the top.
    for (const folder of FOLDER_NAMES) {
      await drive.locator('button:has-text("New")').first().click()
      await drive.waitForTimeout(400)
      await drive.locator('[role=menuitem]:has-text("Folder")').first().click()
      await drive.waitForTimeout(600)
      await drive.locator('input[name="name"]').click()
      await drive.keyboard.press('Control+a')
      await drive.keyboard.type(folder)
      await drive.locator('button:has-text("Create")').last().click()
      await drive.waitForTimeout(800)
    }

    // ---- Curate: 5 files ----
    // Each "New" → file-type click opens an editor in a new tab. We
    // close each one immediately — we don't need editor content in this
    // shot (screenshots.spec.ts handles editor screenshots).
    for (const f of FILE_NAMES) {
      const tabPromise = context.waitForEvent('page', { timeout: 60_000 })
      await drive.bringToFront()
      await drive.locator('button:has-text("New")').first().click()
      await drive.waitForTimeout(400)
      // Note menu items are labeled like "Note (.md)" / "Spreadsheet
      // (.xlsx)" / etc — the unique prefix is enough.
      await drive.locator(`[role=menuitem]:has-text("${f.menuItem}")`).first().click()
      await drive.waitForTimeout(500)
      // Some types prompt for a name; others (xlsx/docx/pptx/whiteboard)
      // auto-suffix and skip the name dialog. Try-and-skip the input.
      const nameInput = drive.locator('input[name="name"]')
      const inputVisible = await nameInput.isVisible().catch(() => false)
      if (inputVisible) {
        await nameInput.click()
        await drive.keyboard.press('Control+a')
        await drive.keyboard.type(f.name)
        await drive.locator('button:has-text("Create")').last().click()
      }
      // Wait for the editor tab; close it without saving.
      const tab = await tabPromise
      await tab.waitForLoadState('domcontentloaded')
      // Brief settle; some editors trigger an autosave on first idle.
      await tab.waitForTimeout(800)
      await tab.close()
      await drive.waitForTimeout(400)
    }

    // ---- Rename auto-named files via the UI rename dialog ----
    // Office + whiteboard creation skips the name dialog (Drive.tsx:551-
    // 558) and auto-suffixes "Untitled.<ext>". Use the right-click
    // context menu → Rename → type new basename to give them curated
    // names. The rename dialog uses a "lockedExt" pattern: the input
    // takes only the basename (no .ext); the .ext is appended outside
    // the input. So we type "Q1 budget", not "Q1 budget.xlsx".
    await drive.bringToFront()
    await drive.reload()
    await drive.waitForLoadState('domcontentloaded')
    await drive.waitForTimeout(2_000)

    for (const f of FILE_NAMES) {
      if (f.menuItem === 'Note') continue // already correctly named
      const oldName = `Untitled.${f.autoExt}`
      const newBase = f.name.replace(`.${f.autoExt}`, '')

      // Right-click the row containing the auto-named file. The
      // FileTable wraps each row in a ContextMenuTrigger; the row's
      // first text content is the filename.
      const row = drive.locator(`tr:has-text("${oldName}")`).first()
      await row.click({ button: 'right' })
      await drive.waitForTimeout(400)
      await drive.locator('[role=menuitem]:has-text("Rename")').first().click()
      await drive.waitForTimeout(500)
      // The rename dialog's input takes the basename only. Select-all
      // and type the new value.
      await drive.locator('input[name="name"]').click()
      await drive.keyboard.press('Control+a')
      await drive.keyboard.type(newBase)
      await drive.locator('button:has-text("Rename")').last().click()
      await drive.waitForTimeout(800)
    }

    // ---- Screenshot ----
    await drive.bringToFront()
    await drive.reload()
    await drive.waitForLoadState('domcontentloaded')
    await drive.waitForTimeout(3_000)
    // Sort by Modified DESC. FileTable.toggleSort defaults Modified to
    // 'desc' on the FIRST click — so a single click is enough.
    await drive.locator('button:has-text("Modified")').first().click()
    await drive.waitForTimeout(800)
    await drive.screenshot({
      path: join(SCREENSHOTS_DIR, '01-drive.png'),
      fullPage: false,
    })
  })
})
