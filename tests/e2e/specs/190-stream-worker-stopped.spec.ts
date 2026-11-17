// The stream route keeps nothing in the service worker
// (docs/plans/drive-block-format.md §4): the browser may stop an idle
// worker at any time, and the next range request starts a fresh one that
// must find the page and its block reader as before. Stopped here between
// two range requests through the DevTools protocol; playback goes on.
// Chromium only (CDP).
import { expect, test } from '../fixtures/test'
import { driveWithSong, playInQuickLook, seekAndPlay } from '../fixtures/stream'

const PASSWORD = 'Deneme123*StreamWorkerStoppedPassword'

test('playback goes on after the service worker is stopped between two range requests', async ({ browser, browserName }) => {
  test.skip(browserName !== 'chromium', 'stopping a service worker needs the DevTools protocol')
  test.slow()
  const context = await browser.newContext()
  const page = await driveWithSong(context, 'swstop', PASSWORD, 'song.wav')
  await playInQuickLook(page, 'song.wav')
  await seekAndPlay(page, 5)

  const cdp = await context.newCDPSession(page)
  await cdp.send('ServiceWorker.enable')
  await cdp.send('ServiceWorker.stopAllWorkers')

  // Another block: a new request, answered by a worker started for it.
  await seekAndPlay(page, 40)
  expect(await page.evaluate(() => navigator.serviceWorker.controller?.scriptURL ?? '')).toContain('/kutup-sw.js')
  await context.close()
})
