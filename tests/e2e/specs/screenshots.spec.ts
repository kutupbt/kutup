import { test } from '@playwright/test'
import { signInOrBootstrap } from '../fixtures/auth'
import { mkdirSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// README screenshot capture. NOT a regression test — re-running this overwrites
// the PNGs in docs/screenshots/ so they stay current with the live UI.
//
// Why one big test instead of one-per-screenshot: each separate test would
// re-bootstrap (login + first-login + mnemonic capture, ~15s) and would
// re-create files. Single sequential test reuses one auth session and seeds
// the file mix once.
//
// Sized to 1280x720 (Playwright's default desktop viewport). All shots are
// viewport-only (fullPage: false) so heights stay uniform when stacked
// vertically in README.md.

const SCREENSHOTS_DIR = join(__dirname, '..', '..', '..', 'docs', 'screenshots')

test.describe('README screenshots', () => {
  test.setTimeout(360_000)

  test('capture drive, notes, xlsx, whiteboard, history, settings', async ({ context }) => {
    mkdirSync(SCREENSHOTS_DIR, { recursive: true })

    const driver = await signInOrBootstrap(context)
    // Force light theme. The app persists 'kutup-theme' in localStorage and
    // toggles the 'dark' class on <html>; emulateMedia alone doesn't flip it.
    async function forceLight(p: typeof driver) {
      await p.evaluate(() => {
        localStorage.setItem('kutup-theme', 'light')
        document.documentElement.classList.remove('dark')
        document.documentElement.classList.add('light')
      })
    }
    await forceLight(driver)
    await driver.reload()
    await driver.waitForLoadState('domcontentloaded')
    await driver.waitForTimeout(2_000)

    // The shared dev stack accumulates files across runs. Note creation
    // collides on "Untitled.md", so we always type a unique-per-run name.
    // Office/whiteboard creation auto-suffixes "Untitled (N).xlsx" so they
    // don't need this trick.
    const stamp = new Date().toISOString().slice(11, 19).replace(/:/g, '')
    const noteName = `Project ideas ${stamp}.md`

    // -------- 02: Notes editor --------
    const noteTabPromise = context.waitForEvent('page', { timeout: 60_000 })
    await driver.locator('button:has-text("New")').first().click()
    await driver.waitForTimeout(500)
    await driver.locator('[role=menuitem]:has-text("Note")').first().click()
    await driver.waitForTimeout(800)
    // Dialog input has autofocus + onFocus selects the basename; replace
    // by selecting all then typing.
    await driver.locator('input[name="name"]').click()
    await driver.keyboard.press('Control+a')
    await driver.keyboard.type(noteName)
    await driver.locator('button:has-text("Create")').last().click()
    const noteTab = await noteTabPromise
    await noteTab.waitForLoadState('domcontentloaded')
    await forceLight(noteTab)
    // y-codemirror.next + WS handshake
    await noteTab.waitForTimeout(7_000)

    // Plain prose only — CodeMirror's markdown extension auto-continues
    // bullet lists on Enter, which mangles "- " line content if you
    // type sequentially. For a screenshot we just want clean paragraphs.
    await noteTab.locator('.cm-content').click()
    await noteTab.keyboard.press('Control+a')
    await noteTab.keyboard.press('Delete')
    const noteText = [
      '# Project ideas',
      '',
      'Scratchpad for the next sprint.',
      '',
      'Real-time collab demo lands in the docs Tuesday.',
      'Then the version-history sidebar scroll fix.',
      'And finally a polish pass on the empty-state copy.',
      '',
      'Everything in this file is end-to-end encrypted.',
      'The server only sees ciphertext.',
    ].join('\n')
    await noteTab.keyboard.type(noteText, { delay: 4 })
    await noteTab.waitForTimeout(1_500)
    await noteTab.screenshot({
      path: join(SCREENSHOTS_DIR, '02-notes-editor.png'),
      fullPage: false,
    })
    await noteTab.close()

    // -------- 03: Xlsx + 05: Version history --------
    const xlsxTabPromise = context.waitForEvent('page', { timeout: 30_000 })
    await driver.bringToFront()
    await driver.locator('button:has-text("New")').first().click()
    await driver.waitForTimeout(500)
    await driver.locator('[role=menuitem]:has-text("Spreadsheet")').first().click()
    const xlsxTab = await xlsxTabPromise
    await xlsxTab.waitForLoadState('domcontentloaded')
    await forceLight(xlsxTab)
    // OO bootstrap is slow (~30s on a warm stack).
    await xlsxTab.waitForTimeout(30_000)

    // Dismiss the "Cell text direction" tutorial popup that overlays the
    // grid in fresh OO sessions. Its "Got it" button sits at (440, 263)
    // — same coordinate the existing xlsx specs click.
    await xlsxTab.bringToFront()
    await xlsxTab.mouse.click(440, 263)
    await xlsxTab.waitForTimeout(500)

    // Type into A1 and a small column underneath so the sheet doesn't look
    // empty in the screenshot. mouse.click into the canvas area + keyboard.
    await xlsxTab.mouse.click(200, 250)
    await xlsxTab.waitForTimeout(800)
    await xlsxTab.keyboard.type('Q1 plan', { delay: 8 })
    await xlsxTab.keyboard.press('Enter')
    await xlsxTab.keyboard.type('Notes', { delay: 8 })
    await xlsxTab.keyboard.press('Enter')
    await xlsxTab.keyboard.type('Office docs', { delay: 8 })
    await xlsxTab.keyboard.press('Enter')
    await xlsxTab.keyboard.type('Whiteboards', { delay: 8 })
    await xlsxTab.keyboard.press('Enter')
    await xlsxTab.keyboard.type('Federation', { delay: 8 })
    await xlsxTab.keyboard.press('Tab')
    await xlsxTab.waitForTimeout(1_500)
    await xlsxTab.screenshot({
      path: join(SCREENSHOTS_DIR, '03-xlsx.png'),
      fullPage: false,
    })

    // Save once so version history has a row, then open the sidebar.
    await xlsxTab.locator('header button[title="Save current state (⌘/Ctrl+S)"]').click()
    await xlsxTab.waitForTimeout(4_000)
    await xlsxTab.locator('header button:has-text("History")').click()
    await xlsxTab.waitForTimeout(2_500)
    await xlsxTab.screenshot({
      path: join(SCREENSHOTS_DIR, '05-version-history.png'),
      fullPage: false,
    })
    await xlsxTab.close()

    // -------- 04: Whiteboard --------
    const wbTabPromise = context.waitForEvent('page', { timeout: 30_000 })
    await driver.bringToFront()
    await driver.locator('button:has-text("New")').first().click()
    await driver.waitForTimeout(500)
    await driver.locator('[role=menuitem]:has-text("Whiteboard")').first().click()
    const wbTab = await wbTabPromise
    await wbTab.waitForLoadState('domcontentloaded')
    await forceLight(wbTab)
    await wbTab.waitForTimeout(9_000)

    // Inject a small composition via the imperative API exposed by
    // WhiteboardEditor — a couple of rectangles + an ellipse + a line, so
    // the canvas reads as "in use" rather than blank.
    await wbTab.evaluate(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const api = (window as any).__EXCALIDRAW_API__
      if (!api) return
      const baseProps = {
        angle: 0,
        strokeColor: '#1e293b',
        backgroundColor: 'transparent',
        fillStyle: 'solid' as const,
        strokeWidth: 2,
        strokeStyle: 'solid' as const,
        roughness: 1,
        opacity: 100,
        groupIds: [],
        frameId: null,
        roundness: { type: 3 },
        boundElements: null,
        link: null,
        locked: false,
        seed: 1,
        version: 1,
        versionNonce: 1,
        isDeleted: false,
        updated: Date.now(),
      }
      const els = [
        { ...baseProps, id: 'r1', type: 'rectangle', x: 240, y: 150, width: 220, height: 96,
          backgroundColor: '#bae6fd', fillStyle: 'solid', index: 'a0' },
        { ...baseProps, id: 't1', type: 'text', x: 280, y: 184, width: 160, height: 28,
          text: 'Notes', fontSize: 24, fontFamily: 1, textAlign: 'center', verticalAlign: 'middle',
          containerId: null, originalText: 'Notes', autoResize: true, lineHeight: 1.25, index: 'a1' },
        { ...baseProps, id: 'r2', type: 'rectangle', x: 540, y: 150, width: 220, height: 96,
          backgroundColor: '#fde68a', fillStyle: 'solid', index: 'a2' },
        { ...baseProps, id: 't2', type: 'text', x: 580, y: 184, width: 160, height: 28,
          text: 'Office', fontSize: 24, fontFamily: 1, textAlign: 'center', verticalAlign: 'middle',
          containerId: null, originalText: 'Office', autoResize: true, lineHeight: 1.25, index: 'a3' },
        { ...baseProps, id: 'r3', type: 'ellipse', x: 380, y: 320, width: 220, height: 96,
          backgroundColor: '#bbf7d0', fillStyle: 'solid', roundness: null, index: 'a4' },
        { ...baseProps, id: 't3', type: 'text', x: 416, y: 354, width: 150, height: 28,
          text: 'Whiteboards', fontSize: 22, fontFamily: 1, textAlign: 'center', verticalAlign: 'middle',
          containerId: null, originalText: 'Whiteboards', autoResize: true, lineHeight: 1.25, index: 'a5' },
        { ...baseProps, id: 'l1', type: 'arrow', x: 360, y: 246, width: 60, height: 70,
          points: [[0, 0], [60, 70]], lastCommittedPoint: null,
          startBinding: null, endBinding: null,
          startArrowhead: null, endArrowhead: 'arrow',
          elbowed: false, index: 'a6' },
        { ...baseProps, id: 'l2', type: 'arrow', x: 580, y: 246, width: -50, height: 70,
          points: [[0, 0], [-50, 70]], lastCommittedPoint: null,
          startBinding: null, endBinding: null,
          startArrowhead: null, endArrowhead: 'arrow',
          elbowed: false, index: 'a7' },
      ]
      api.updateScene({ elements: els })
    })
    await wbTab.waitForTimeout(2_500)
    await wbTab.screenshot({
      path: join(SCREENSHOTS_DIR, '04-whiteboard.png'),
      fullPage: false,
    })
    await wbTab.close()

    // -------- 01: Drive (now populated) --------
    await driver.bringToFront()
    await driver.reload()
    await driver.waitForLoadState('domcontentloaded')
    await driver.waitForTimeout(3_000)
    // The shared dev stack accumulates files. Sort by Modified descending
    // so the freshly-created demo files (note + xlsx + whiteboard) appear
    // at the top. FileTable's toggleSort defaults the Modified column to
    // 'desc' on the FIRST click — clicking twice would flip back to asc.
    await driver.locator('button:has-text("Modified")').first().click()
    await driver.waitForTimeout(800)
    await driver.screenshot({
      path: join(SCREENSHOTS_DIR, '01-drive.png'),
      fullPage: false,
    })

    // -------- 06: Settings --------
    await driver.goto('/settings')
    await driver.waitForLoadState('domcontentloaded')
    await driver.waitForTimeout(2_500)
    await driver.screenshot({
      path: join(SCREENSHOTS_DIR, '06-settings.png'),
      fullPage: false,
    })
  })
})
