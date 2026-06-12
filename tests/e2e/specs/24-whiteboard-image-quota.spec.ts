import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

// Whiteboard image-asset quota regression. Proves three things:
//   1. Pasting an image charges the user's storage_used_bytes by ~the
//      ciphertext size (nonce + AAD-bound AEAD payload).
//   2. Deleting the parent whiteboard releases those bytes.
//   3. The counter never goes negative.
//
// We don't need a precise byte match — the encrypted-at-rest format adds
// a 24-byte nonce + 16-byte tag, and Excalidraw's snapshot save also
// charges main-file bytes. So the assertions are "increased by at least
// the dataURL length" and "decreased by at least the dataURL length"
// after paste / delete respectively.

const ONE_PX_PNG_DATAURL =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgAAIAAAUAAeImBZsAAAAASUVORK5CYII='

async function readUsedBytes(page: import('@playwright/test').Page): Promise<number> {
  // The app stores its access token in Redux (in-memory), so a plain
  // page-side `fetch('/api/user/me')` is unauth'd. The refresh-token
  // cookie is httpOnly + auto-attached, so we mint a fresh access token
  // via /auth/refresh and use it for the me-call.
  const used = await page.evaluate(async () => {
    const refreshRes = await fetch('/api/auth/refresh', {
      method: 'POST', credentials: 'include',
    })
    if (!refreshRes.ok) throw new Error('refresh failed: ' + refreshRes.status)
    const { accessToken } = await refreshRes.json()
    const meRes = await fetch('/api/user/me', {
      headers: { Authorization: 'Bearer ' + accessToken },
    })
    if (!meRes.ok) throw new Error('me failed: ' + meRes.status)
    const me = await meRes.json()
    return me.storageUsedBytes as number
  })
  return used
}

test('whiteboard — pasting image charges quota; deleting releases it', async ({ context }) => {
  const drive = await signInOrBootstrap(context)

  const baselineUsed = await readUsedBytes(drive)

  // Create whiteboard.
  const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
  await drive.locator('button:has-text("New")').first().click()
  await drive.waitForTimeout(500)
  await drive.locator('[role=menuitem]:has-text("Whiteboard")').first().click()
  const tabA = await tabAPromise
  await tabA.waitForLoadState('domcontentloaded')
  await tabA.waitForTimeout(8_000)

  await tabA.evaluate((dataURL) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const api = (window as any).__EXCALIDRAW_API__
    if (!api) throw new Error('no api on tab A')
    const fid = 'kutup-q-' + Math.random().toString(36).slice(2, 12)
    api.addFiles([{ id: fid, mimeType: 'image/png', dataURL, created: Date.now() }])
    const el = {
      id: 'kutup-q-el-' + Math.random().toString(36).slice(2, 10),
      type: 'image', fileId: fid, status: 'pending',
      x: 100, y: 100, width: 100, height: 100,
      angle: 0, strokeColor: 'transparent', backgroundColor: 'transparent',
      fillStyle: 'solid', strokeWidth: 1, strokeStyle: 'solid',
      roughness: 0, opacity: 100,
      groupIds: [], frameId: null, roundness: null,
      seed: 1, version: 1, versionNonce: 1, isDeleted: false,
      boundElements: null, updated: Date.now(),
      link: null, locked: false, index: 'a0',
      scale: [1, 1], crop: null,
    }
    api.updateScene({ elements: [...api.getSceneElements(), el] })
  }, ONE_PX_PNG_DATAURL)

  // Wait for upload + DB commit.
  await tabA.waitForTimeout(5_000)

  const afterPasteUsed = await readUsedBytes(drive)
  expect(afterPasteUsed,
    'storage_used_bytes increased after image paste'
  ).toBeGreaterThan(baselineUsed)
  // Lower bound: the dataURL itself, encrypted, is at minimum dataURL.length
  // bytes + the 24-byte nonce + the 16-byte tag.
  expect(afterPasteUsed - baselineUsed,
    'increase covers at least the dataURL plaintext length'
  ).toBeGreaterThanOrEqual(ONE_PX_PNG_DATAURL.length)

  // Locate the new whiteboard's row in Drive and delete it. Use the file
  // url from tabA to find the id, then call the API directly — the Drive
  // UI's delete dialog has too many moving parts to drive reliably.
  const fileUrl = tabA.url()
  const fileId = fileUrl.split('/').filter(Boolean).pop()
  if (!fileId) throw new Error('cannot extract fileId from ' + fileUrl)

  await tabA.close()

  await drive.evaluate(async (fid) => {
    const refreshRes = await fetch('/api/auth/refresh', {
      method: 'POST', credentials: 'include',
    })
    const { accessToken } = await refreshRes.json()
    // DELETE /files soft-deletes into the trash — quota stays held while
    // trashed (by design; see docs/api.md → Trash). The permanent purge
    // (DELETE /trash/:id) is what releases the quota.
    await fetch('/api/files/' + fid, {
      method: 'DELETE',
      headers: { Authorization: 'Bearer ' + accessToken },
    })
    await fetch('/api/trash/' + fid, {
      method: 'DELETE',
      headers: { Authorization: 'Bearer ' + accessToken },
    })
  }, fileId)

  // The purge runs the quota release inside a tx and returns 204
  // immediately; counter should be authoritative when the DELETE returns.
  await drive.waitForTimeout(500)

  const afterDeleteUsed = await readUsedBytes(drive)
  expect(afterDeleteUsed,
    'storage_used_bytes released back near baseline after trash purge'
  ).toBeLessThanOrEqual(baselineUsed + 100) // small slack for any other test artifacts
  expect(afterDeleteUsed,
    'storage_used_bytes never goes negative'
  ).toBeGreaterThanOrEqual(0)
})
