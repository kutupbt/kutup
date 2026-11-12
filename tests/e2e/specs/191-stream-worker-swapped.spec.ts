// A new service worker takes over mid-playback
// (docs/plans/drive-block-format.md §4): it skips waiting and claims the
// page, and since the stream route keeps nothing in the worker, the next
// range request is answered by the new one with no stream to hand over.
import { expect, test } from '@playwright/test'
import { driveWithSong, playInQuickLook, seekAndPlay } from '../fixtures/stream'

const PASSWORD = 'Deneme123*StreamWorkerSwappedPassword'

test('playback goes on when the worker script is replaced mid-playback', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  const page = await driveWithSong(context, 'swswap', PASSWORD, 'song.wav')
  await playInQuickLook(page, 'song.wav')
  await seekAndPlay(page, 5)

  // Another script URL is another worker script: it installs, skips
  // waiting and claims this page, as a deploy's new worker does.
  const swapped = await page.evaluate(async () => {
    const changed = new Promise<void>((resolve) => navigator.serviceWorker.addEventListener('controllerchange', () => resolve(), { once: true }))
    await navigator.serviceWorker.register('/kutup-sw.js?swap=1', { scope: '/', updateViaCache: 'none' })
    await changed
    return navigator.serviceWorker.controller?.scriptURL ?? ''
  })
  expect(swapped).toContain('/kutup-sw.js?swap=1')

  await seekAndPlay(page, 40)
  await context.close()
})
