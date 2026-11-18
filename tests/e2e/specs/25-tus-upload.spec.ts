// E2E coverage for the tus.io streaming upload path.
//
// Unit tests prove the wire format; this spec proves the protocol against a
// real server: a real Chromium loads the production Drive bundle, seals a
// multi-block file (docs/plans/drive-block-format.md) and sends it as one tus
// POST plus PATCHes, then commits its revision.
//
// Confidence we want from this spec:
//   1. A multi-PATCH upload completes — exercises the PATCH loop, not just
//      the single-shot path.
//   2. The file appears in the Drive list under its original name.
//   3. The bounded-memory multipart fallback (/api/v1/drive/files) is not
//      used for an ordinary upload.

import { expect, test } from '../fixtures/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*TusUploadPassword'
// 20 MiB plaintext → 5 sealed 4 MiB blocks. A PATCH carries two (above S3's
// 5 MiB minimum part), so three PATCHes, the non-final ones exercising the
// part rules.
const FILE_BYTES = 20 * 1024 * 1024

test('uploads a 20 MiB file via the tus endpoint and lands it in Drive', async ({ browser }) => {
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
    if (request.method() === 'POST' && pathname === '/api/v1/drive/files') multipart.push(pathname)
  })
  page.on('response', (response) => {
    const { pathname } = new URL(response.url())
    if (response.request().method() === 'PATCH' && /^\/api\/uploads\/[^/]+$/.test(pathname) && response.ok()) {
      tusPatches.push(pathname)
    }
  })

  // A deterministic pattern (byte i = (i * 31 + 7) & 0xff) catches sloppy
  // zero-fill bugs that pass on all-zeros input.
  const fileName = `tus-20mib-${Date.now()}.bin`
  const buffer = Buffer.alloc(FILE_BYTES)
  for (let i = 0; i < FILE_BYTES; i++) buffer[i] = (i * 31 + 7) & 0xff

  await page.getByRole('button', { name: 'New' }).first().click()
  const [chooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.getByRole('menuitem', { name: 'Upload files' }).click(),
  ])
  await chooser.setFiles({ name: fileName, mimeType: 'application/octet-stream', buffer })

  await expect(page.getByText(fileName, { exact: true }).first()).toBeVisible({ timeout: 90_000 })
  // Two blocks per PATCH: three for five blocks, the last one carrying the
  // sealed manifest and leaving the uploaded revision its commit makes current.
  await expect.poll(() => tusPatches.length, { timeout: 90_000 }).toBeGreaterThanOrEqual(3)
  expect(tusPosts.length).toBe(1)
  expect(new Set(tusPatches).size).toBe(1)
  expect(multipart).toEqual([])

  // The listing comes from the server, not the upload's optimistic state.
  await page.reload()
  await expect(page.getByText(fileName, { exact: true }).first()).toBeVisible({ timeout: 60_000 })
  await context.close()
})
