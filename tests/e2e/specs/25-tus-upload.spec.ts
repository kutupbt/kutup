// E2E coverage for the tus.io streaming upload path.
//
// Unit tests prove the wire format; this spec proves the protocol against a
// real server: a real Chromium loads the production Drive bundle, encrypts a
// multi-chunk file and sends it as one tus POST plus PATCHes.
//
// Confidence we want from this spec:
//   1. A multi-chunk upload (≥ 2× 5 MB) completes — exercises the PATCH
//      loop, not just the single-shot path.
//   2. The file appears in the Drive list under its original name.
//   3. The bounded-memory multipart fallback (/api/files/upload) is not
//      used for an ordinary upload.

import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*TusUploadPassword'
// 12 MB plaintext → 3 secretstream chunks, sized just over 2 × 5 MB so the
// non-final 5 MB part rules are exercised.
const FILE_BYTES = 12 * 1024 * 1024

test('uploads a 12 MB file via the tus endpoint and lands it in Drive', async ({ browser }) => {
  test.slow()
  const account = newAccount('tus', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, account)
  const page = await openDrive(context)

  const tusPosts: string[] = []
  const tusPatches: string[] = []
  const multipart: string[] = []
  page.on('request', (request) => {
    const { pathname } = new URL(request.url())
    if (request.method() === 'POST' && /^\/api\/uploads\/?$/.test(pathname)) tusPosts.push(pathname)
    if (request.method() === 'POST' && pathname === '/api/files/upload') multipart.push(pathname)
  })
  page.on('response', (response) => {
    const { pathname } = new URL(response.url())
    if (response.request().method() === 'PATCH' && /^\/api\/uploads\/[^/]+$/.test(pathname) && response.ok()) {
      tusPatches.push(pathname)
    }
  })

  // A deterministic pattern (byte i = (i * 31 + 7) & 0xff) catches sloppy
  // zero-fill bugs that pass on all-zeros input.
  const fileName = `tus-12mb-${Date.now()}.bin`
  const buffer = Buffer.alloc(FILE_BYTES)
  for (let i = 0; i < FILE_BYTES; i++) buffer[i] = (i * 31 + 7) & 0xff

  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.getByRole('menuitem', { name: 'Upload files' }).click(),
  ])
  await chooser.setFiles({ name: fileName, mimeType: 'application/octet-stream', buffer })

  await expect(page.getByText(fileName, { exact: true }).first()).toBeVisible({ timeout: 90_000 })
  // One secretstream chunk per PATCH: three for 12 MB, the last one
  // finalising the file.
  await expect.poll(() => tusPatches.length, { timeout: 90_000 }).toBeGreaterThanOrEqual(3)
  expect(tusPosts.length).toBe(1)
  expect(new Set(tusPatches).size).toBe(1)
  expect(multipart).toEqual([])

  // The listing comes from the server, not the upload's optimistic state.
  await page.reload()
  await expect(page.getByText(fileName, { exact: true }).first()).toBeVisible({ timeout: 60_000 })
  await context.close()
})
