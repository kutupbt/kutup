import { expect, type BrowserContext, type Page } from '@playwright/test'

/**
 * The whiteboard editor exposes Excalidraw's API as window.__EXCALIDRAW_API__
 * for these specs (WhiteboardEditor.tsx); scenes are read and changed
 * through it rather than by drawing with the mouse.
 */
export async function createWhiteboard(drive: Page): Promise<string> {
  await drive.getByRole('button', { name: 'New' }).first().click()
  await drive.getByRole('menuitem', { name: 'Whiteboard', exact: true }).click()
  await drive.waitForURL(/\/file\//, { timeout: 60_000 })
  await whiteboardReady(drive)
  return drive.url()
}

export async function whiteboardReady(page: Page) {
  await expect(page.locator('canvas').first()).toBeVisible({ timeout: 60_000 })
  await expect
    .poll(() => page.evaluate(() => Boolean((window as unknown as { __EXCALIDRAW_API__?: unknown }).__EXCALIDRAW_API__)), {
      timeout: 60_000,
    })
    .toBe(true)
}

export async function openWhiteboard(context: BrowserContext, url: string): Promise<Page> {
  const page = await context.newPage()
  await page.goto(url)
  await whiteboardReady(page)
  return page
}

export async function elementCount(page: Page): Promise<number> {
  return page.evaluate(() => {
    const api = (window as unknown as { __EXCALIDRAW_API__: { getSceneElements(): unknown[] } }).__EXCALIDRAW_API__
    return api.getSceneElements().length
  })
}

const BASE = {
  angle: 0,
  strokeColor: '#000000',
  backgroundColor: 'transparent',
  fillStyle: 'solid',
  strokeWidth: 2,
  strokeStyle: 'solid',
  roughness: 1,
  opacity: 100,
  groupIds: [],
  frameId: null,
  roundness: null,
  seed: 1,
  version: 1,
  versionNonce: 1,
  isDeleted: false,
  boundElements: null,
  link: null,
  locked: false,
  index: 'a0',
}

/** Adds a rectangle to the scene, as drawing one would. */
export async function addRectangle(page: Page) {
  await page.evaluate((base) => {
    const api = (window as unknown as { __EXCALIDRAW_API__: any }).__EXCALIDRAW_API__
    const element = { ...base, id: `rect-${Math.random().toString(36).slice(2, 10)}`, type: 'rectangle', x: 100, y: 100, width: 200, height: 100, updated: Date.now() }
    api.updateScene({ elements: [...api.getSceneElements(), element] })
  }, BASE)
}

export const ONE_PX_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgAAIAAAUAAeImBZsAAAAASUVORK5CYII='

/** Pastes an image: its file (an encrypted asset) and its element. */
export async function addImage(page: Page, dataURL = ONE_PX_PNG) {
  await page.evaluate(
    ({ base, dataURL }) => {
      const api = (window as unknown as { __EXCALIDRAW_API__: any }).__EXCALIDRAW_API__
      const fileId = `img-${Math.random().toString(36).slice(2, 12)}`
      api.addFiles([{ id: fileId, mimeType: 'image/png', dataURL, created: Date.now() }])
      const element = {
        ...base,
        id: `img-el-${Math.random().toString(36).slice(2, 10)}`,
        type: 'image',
        fileId,
        status: 'pending',
        x: 100,
        y: 100,
        width: 100,
        height: 100,
        strokeColor: 'transparent',
        strokeWidth: 1,
        roughness: 0,
        scale: [1, 1],
        crop: null,
        updated: Date.now(),
      }
      api.updateScene({ elements: [...api.getSceneElements(), element] })
    },
    { base: BASE, dataURL },
  )
}

/** Whether this page has the scene's image and its decrypted file. */
export async function hasImage(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    const api = (window as unknown as { __EXCALIDRAW_API__: any }).__EXCALIDRAW_API__
    const image = (api.getSceneElements() as Array<{ type: string; fileId?: string }>).find((e) => e.type === 'image' && e.fileId)
    return Boolean(image && api.getFiles()[image.fileId!]?.dataURL)
  })
}

/** Saves the current state and waits for the server to take it. */
export async function saveState(page: Page) {
  const saved = page.waitForResponse((response) => response.request().method() !== 'GET' && /^\/api\/files\/[^/]+/.test(new URL(response.url()).pathname) && response.ok())
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await saved
}

export function historyPanel(page: Page) {
  return page.getByRole('complementary').filter({ has: page.getByRole('heading', { name: 'Version history' }) })
}
