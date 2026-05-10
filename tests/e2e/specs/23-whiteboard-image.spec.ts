import { test, expect } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'

// Whiteboard image-asset regression: tab A injects an image element + its
// binary; tab B receives the element through EXCALIDRAW_OP, fetches the
// asset blob over HTTP, and ends up with both the element AND a populated
// appState.files entry. Proves the Excalidraw-native status flow:
//   A: paste → status "pending" → upload + flip to "saved" → broadcast
//   B: receive element with status "saved" → GET /assets/:id → addFiles
//
// Real PNG bytes don't matter — we're proving the wire path, not the
// renderer. The 1×1 base64 dataURL keeps the spec tiny.

const ONE_PX_PNG_DATAURL =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgAAIAAAUAAeImBZsAAAAASUVORK5CYII='

test('whiteboard — image pasted on tab A appears on tab B via asset blob', async ({ context }) => {
  const page = await signInOrBootstrap(context)

  const tabAPromise = context.waitForEvent('page', { timeout: 30_000 })
  await page.locator('button:has-text("New")').first().click()
  await page.waitForTimeout(500)
  await page.locator('[role=menuitem]:has-text("Whiteboard")').first().click()
  const tabA = await tabAPromise
  await tabA.waitForLoadState('domcontentloaded')
  const fileUrl = tabA.url()

  const tabB = await context.newPage()
  await tabB.goto(fileUrl)
  await tabB.waitForLoadState('domcontentloaded')

  // WhiteboardEditor's WS handshake takes a few seconds to complete.
  await tabA.waitForTimeout(8_000)
  await tabB.waitForTimeout(8_000)

  // Tab A: addFiles + add an image element with status "pending". The
  // editor's onChange watcher will see the pending image, encrypt-upload,
  // then mutate to status "saved" — which broadcasts to tab B.
  await tabA.evaluate((dataURL) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const api = (window as any).__EXCALIDRAW_API__
    if (!api) throw new Error('no api on tab A')
    const fid = 'kutup-img-' + Math.random().toString(36).slice(2, 12)
    api.addFiles([{
      id: fid,
      mimeType: 'image/png',
      dataURL,
      created: Date.now(),
    }])
    const el = {
      id: 'kutup-img-el-' + Math.random().toString(36).slice(2, 10),
      type: 'image',
      fileId: fid,
      status: 'pending',
      x: 100, y: 100,
      width: 100, height: 100,
      angle: 0,
      strokeColor: 'transparent',
      backgroundColor: 'transparent',
      fillStyle: 'solid',
      strokeWidth: 1,
      strokeStyle: 'solid',
      roughness: 0,
      opacity: 100,
      groupIds: [],
      frameId: null,
      roundness: null,
      seed: 1,
      version: 1,
      versionNonce: 1,
      isDeleted: false,
      boundElements: null,
      updated: Date.now(),
      link: null,
      locked: false,
      index: 'a0',
      scale: [1, 1],
      crop: null,
    }
    api.updateScene({ elements: [...api.getSceneElements(), el] })
  }, ONE_PX_PNG_DATAURL)

  // Allow time for: onChange → uploadAsset → status flip → debounced
  // broadcast (200ms) → tab B reconcile → fetchAsset → addFiles.
  // The HTTP round-trip can take 1-2s on a cold backend so we give it
  // generous slack.
  await tabA.waitForTimeout(6_000)

  // Tab B should now have both the element and the binary in its files
  // map. Probe both — element-only would mean the asset GET failed.
  const tabBState = await tabB.evaluate(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const api = (window as any).__EXCALIDRAW_API__
    if (!api) return { hasElement: false, hasFile: false }
    const els = api.getSceneElements() as Array<{ type: string; fileId?: string }>
    const img = els.find((e) => e.type === 'image' && !!e.fileId)
    if (!img || !img.fileId) return { hasElement: false, hasFile: false }
    const files = api.getFiles() as Record<string, { dataURL?: string }>
    return {
      hasElement: true,
      hasFile: !!files[img.fileId]?.dataURL,
      fileId: img.fileId,
    }
  })

  expect(tabBState.hasElement, 'tab B saw the image element').toBe(true)
  expect(tabBState.hasFile, 'tab B fetched + decrypted the asset blob').toBe(true)
})
