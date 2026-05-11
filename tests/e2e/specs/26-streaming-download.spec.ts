// E2E coverage for the streaming-download path.
//
// Upload a deterministic 12 MB file via the tus endpoint (which Slice
// 3 already covers), then download it through the new streamDownload
// pipeline and assert byte-exact round-trip.
//
// Playwright's Chromium ships the File System Access API, so the
// production code path is the showSaveFilePicker WritableStream
// branch. We can't drive a native save picker from the test runner —
// so we force the Blob-fallback branch by deleting
// `window.showSaveFilePicker` via addInitScript. That uses the same
// streaming decryptor but writes to an in-memory Blob and triggers
// `<a download>`, which Playwright catches via `page.on('download')`.
// The decrypt path is the same; only the sink differs.

import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'
import { createHash } from 'node:crypto'
import * as fs from 'node:fs/promises'

const FILE_NAME = `tus-roundtrip-12mb-${Date.now()}.bin`
const FILE_BYTES = 12 * 1024 * 1024

test.describe('streaming download', () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
    await signInOrBootstrap(ctx)
    await ctx.close()
  })

  test('uploads a 12 MB file via tus, downloads it via streamDownload, bytes match', async ({ context }) => {
    // Force the Blob-fallback branch in streamDownload so we can catch
    // the resulting <a download> via Playwright's downloads API. The
    // production code that decrypts is identical; only the sink
    // differs.
    await context.addInitScript(() => {
      // @ts-expect-error — deleting a feature-detected method
      delete window.showSaveFilePicker
    })

    const page = await signInOrBootstrap(context)
    await page.waitForURL(/\/drive/, { timeout: 30_000 })
    await expect(page.getByRole('heading', { name: /folders/i })).toBeVisible({ timeout: 30_000 })

    // Build a deterministic 12 MB buffer + its sha256 expectation.
    const original = Buffer.alloc(FILE_BYTES)
    for (let i = 0; i < FILE_BYTES; i++) original[i] = (i * 31 + 7) & 0xff
    const originalHash = createHash('sha256').update(original).digest('hex')

    // 1. Upload via the tus pipeline (Slice 3 path).
    const [fileChooser] = await Promise.all([
      page.waitForEvent('filechooser'),
      page.getByRole('button', { name: /^upload$/i }).click(),
    ])
    await fileChooser.setFiles({
      name: FILE_NAME,
      mimeType: 'application/octet-stream',
      buffer: original,
    })
    await expect(page.getByText(FILE_NAME, { exact: false })).toBeVisible({ timeout: 60_000 })

    // 2. Open the file row's context menu (right-click) and click
    //    Download. The context menu is the most reliably-locatable
    //    surface — every row exposes it, including in dense lists.
    const row = page.getByText(FILE_NAME, { exact: false }).first()
    await row.scrollIntoViewIfNeeded()
    await row.click({ button: 'right' })

    // streamDownload's Blob fallback creates an `<a download>` and
    // clicks it — Playwright catches that via `page.on('download')`.
    const downloadPromise = page.waitForEvent('download', { timeout: 60_000 })
    await page.getByRole('menuitem', { name: /download/i }).click()
    const download = await downloadPromise

    // 3. Save the downloaded file to a temp path + compare sha256.
    const dlPath = `/tmp/playwright-dl-${Date.now()}.bin`
    await download.saveAs(dlPath)
    try {
      const downloadedBytes = await fs.readFile(dlPath)
      expect(downloadedBytes.length).toBe(FILE_BYTES)
      const downloadedHash = createHash('sha256').update(downloadedBytes).digest('hex')
      expect(downloadedHash).toBe(originalHash)
    } finally {
      await fs.unlink(dlPath).catch(() => {})
    }
  })
})
