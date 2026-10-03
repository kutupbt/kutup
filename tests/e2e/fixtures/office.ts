import { expect, type Browser, type BrowserContext, type Frame, type Page } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from './apps'

/**
 * ONLYOFFICE runs client-side in the office app's sandboxed origin, framed by
 * Drive's editor page (docs/onlyoffice.md). Its bridge (inner.html) logs
 * `[kutup-bridge]` lines the specs read: outbound changes, applied remote
 * changes, cursor frames, and document readiness.
 */
export type OfficeKind = 'Document' | 'Spreadsheet' | 'Presentation'

export interface OfficeTab {
  page: Page
  logs: string[]
}

function collectBridgeLogs(page: Page): string[] {
  const logs: string[] = []
  page.on('console', (message) => {
    const text = message.text()
    if (text.includes('[kutup-bridge]')) logs.push(text)
  })
  return logs
}

/** Creates an office file from Drive's New menu; returns its editor URL. */
export async function createOffice(drive: Page, kind: OfficeKind): Promise<string> {
  await drive.getByRole('button', { name: 'New' }).first().click()
  await drive.getByRole('menuitem', { name: kind, exact: true }).click()
  await drive.waitForURL(/\/file\//, { timeout: 60_000 })
  return drive.url()
}

/** Opens the editor at `url` in a new tab and waits until its document is open. */
export async function openOffice(context: BrowserContext, url: string): Promise<OfficeTab> {
  const page = await context.newPage()
  const logs = collectBridgeLogs(page)
  await page.goto(url)
  await officeReady({ page, logs })
  return { page, logs }
}

/** The document is open: the bridge logs it once ONLYOFFICE reports ready. */
export async function officeReady(tab: OfficeTab, since = 0) {
  await expect
    .poll(() => tab.logs.slice(since).some((line) => line.includes('Cmd/Ctrl+S bound')), {
      timeout: 120_000,
      message: 'ONLYOFFICE did not report its document ready',
    })
    .toBe(true)
  // The editor lays out its first frame just after it reports ready.
  await tab.page.waitForTimeout(1_000)
  await dismissTips(tab.page)
}

/** Closes ONLYOFFICE's "New feature" tips, which sit over the document. */
export async function dismissTips(page: Page) {
  for (const frame of page.frames()) {
    const tips = frame.getByRole('button', { name: 'Got it', exact: true })
    for (let i = await tips.count().catch(() => 0); i > 0; i--) {
      await tips.first().click({ timeout: 2_000 }).catch(() => {})
    }
  }
}

/** Reloads the editor tab and waits until the document is open again. */
export async function reloadOffice(tab: OfficeTab) {
  const since = tab.logs.length
  await tab.page.reload()
  await officeReady(tab, since)
}

/** Changes this tab sent that carried content. */
export function outboundChanges(tab: OfficeTab): number {
  return tab.logs.filter((line) => line.includes('outbound saveChanges') && /raw=[1-9]\d*/.test(line)).length
}

/** Changes from other tabs this tab applied. */
export function appliedRemote(tab: OfficeTab): number {
  return tab.logs.filter((line) => line.includes('applying remote op')).length
}

export function outboundCursors(tab: OfficeTab): number {
  return tab.logs.filter((line) => line.includes('outbound cursor')).length
}

export function appliedCursors(tab: OfficeTab): number {
  return tab.logs.filter((line) => line.includes('applying remote cursor')).length
}

/** The frame running ONLYOFFICE's editor (`window.editor`), cross-origin to Drive. */
export async function editorFrame(page: Page): Promise<Frame> {
  let found: Frame | undefined
  await expect
    .poll(
      async () => {
        for (const frame of page.frames()) {
          const has = await frame
            .evaluate(() => {
              const w = window as unknown as Record<string, unknown>
              return Boolean(w.editor || w.editorDoc || w.editorCell)
            })
            .catch(() => false)
          if (has) {
            found = frame
            return true
          }
        }
        return false
      },
      { timeout: 60_000, message: 'no ONLYOFFICE editor frame' },
    )
    .toBe(true)
  return found!
}

/** How many canvases ONLYOFFICE drew (zero when the editor failed to load). */
export async function editorCanvases(page: Page): Promise<number> {
  const frame = await editorFrame(page)
  return frame.locator('canvas').count()
}

/** Types in the document body at the page point (x, y). */
export async function typeAt(tab: OfficeTab, x: number, y: number, text: string) {
  await tab.page.bringToFront()
  await tab.page.mouse.click(x, y)
  await tab.page.keyboard.type(text, { delay: 60 })
}

/** Where typing lands in a fresh file of each kind (a 1280×720 window). */
export const WRITE_AT: Record<OfficeKind, { x: number; y: number; open?: 'dblclick' }> = {
  Document: { x: 640, y: 300 },
  Spreadsheet: { x: 162, y: 237 },
  Presentation: { x: 760, y: 330, open: 'dblclick' },
}

/** Types into a fresh file where each kind takes text (a slide's title). */
export async function write(tab: OfficeTab, kind: OfficeKind, text: string, at = WRITE_AT[kind]) {
  await tab.page.bringToFront()
  if (at.open === 'dblclick') await tab.page.mouse.dblclick(at.x, at.y)
  else await tab.page.mouse.click(at.x, at.y)
  await tab.page.keyboard.type(text, { delay: 60 })
}

/** A new account's new office file of `kind`, not yet opened. */
export async function freshOfficeFile(browser: Browser, kind: OfficeKind, password: string) {
  const context = await browser.newContext()
  await registerAccount(context, newAccount(`off${kind.slice(0, 3).toLowerCase()}`, password))
  const drive = await openDrive(context)
  const url = await createOffice(drive, kind)
  await drive.close()
  return { context, url }
}
