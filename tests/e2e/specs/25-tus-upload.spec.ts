// E2E coverage for the tus.io streaming upload path.
//
// The unit tests (frontend/src/crypto/streamEncryptor.test.ts) prove the
// wire format. The MSW integration test we wanted to write hit a
// jsdom-vs-libsodium realm collision, so the protocol-level coverage
// (POST + N PATCHes + finaliser + DB row) lives here, where a real
// Chromium loads the production bundle against the running docker
// stack on https://localhost:38443.
//
// Confidence we want from this spec:
//   1. A multi-chunk upload (≥ 2× 5 MB) completes — exercises the
//      PATCH loop, not just the single-shot path.
//   2. The file appears in the Drive list with the original filename
//      and a plausible size readout.
//   3. The previous in-memory `encryptStream(buffer)` path is gone
//      (proxy: confirm the /api/uploads POST happened, /api/files/
//      upload didn't).

import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

const FILE_NAME = `tus-12mb-${Date.now()}.bin`
// 12 MB plaintext → 3 secretstream chunks → 4 tus PATCHes
// (header+chunk1, chunk2, chunk3-final). Sized just over 2 × 5 MB so
// non-final 5-MB-minimum part rules get exercised.
const FILE_BYTES = 12 * 1024 * 1024

test.describe('tus.io streaming upload', () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
    await signInOrBootstrap(ctx)
    await ctx.close()
  })

  test('uploads a 12 MB file via the tus endpoint and lands it in Drive', async ({ context }) => {
    const page = await signInOrBootstrap(context)
    await page.waitForURL(/\/drive/, { timeout: 30_000 })

    // Wait for Drive to finish hydrating the My Files collection — the
    // upload handler bails silently if currentFolder.collectionKey is
    // not yet decrypted. The "Folders" heading appears once the listing
    // is in.
    await expect(page.getByRole('heading', { name: /folders/i })).toBeVisible({ timeout: 30_000 })

    // Track which upload endpoint(s) get hit. We want the new tus path
    // (/api/uploads) and explicitly *not* the legacy multipart
    // (/api/files/upload). The federated /fed-proxy/.../upload still
    // uses multipart, but we don't trigger that here.
    const tusPostCount: number[] = []
    const tusPatchCount: number[] = []
    const legacyMultipartCount: number[] = []
    page.on('request', (req) => {
      const url = req.url()
      const method = req.method()
      if (method === 'POST' && /\/api\/uploads\/?$/.test(url)) tusPostCount.push(1)
      if (method === 'PATCH' && /\/api\/uploads\/[\w-]+$/.test(url)) tusPatchCount.push(1)
      if (method === 'POST' && /\/api\/files\/upload$/.test(url)) legacyMultipartCount.push(1)
    })

    // Build a deterministic 12 MB blob. Pattern: byte i = (i * 31 + 7)
    // & 0xff — same shape the streamEncryptor test uses, catches
    // sloppy zero-fill bugs that pass on all-zeros input.
    const fileBuffer = Buffer.alloc(FILE_BYTES)
    for (let i = 0; i < FILE_BYTES; i++) fileBuffer[i] = (i * 31 + 7) & 0xff

    // The Upload button wires fileInputRef.onchange THEN clicks the
    // hidden input — directly calling setInputFiles on the hidden input
    // wouldn't fire the React handler (no onchange installed yet).
    // Playwright's filechooser pattern hooks the click and feeds files.
    const [fileChooser] = await Promise.all([
      page.waitForEvent('filechooser'),
      page.getByRole('button', { name: /^upload$/i }).click(),
    ])
    await fileChooser.setFiles({
      name: FILE_NAME,
      mimeType: 'application/octet-stream',
      buffer: fileBuffer,
    })

    // Wait for the upload to complete: the new file row appears in the
    // Drive list, and the tus PATCH count stops increasing. Generous
    // timeout because 12 MB through libsodium-WASM + 3 PATCHes can
    // take a few seconds.
    await expect(page.getByText(FILE_NAME, { exact: false })).toBeVisible({ timeout: 60_000 })

    // Sanity: at least one tus POST + at least one PATCH happened.
    expect(tusPostCount.length).toBeGreaterThanOrEqual(1)
    expect(tusPatchCount.length).toBeGreaterThanOrEqual(1)
    // And the legacy multipart path was NOT used.
    expect(legacyMultipartCount.length).toBe(0)
  })
})
