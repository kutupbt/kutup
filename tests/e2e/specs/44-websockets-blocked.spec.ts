import { expect, test, type Page } from '@playwright/test'
import { appOrigin, appUrl, newAccount, registerAccount } from '../fixtures/apps'

const PASSWORD = 'Deneme123*BlockedSocketsPassword'

/**
 * A gateway that lets HTTPS through but refuses every WebSocket upgrade:
 * each socket fails and closes without ever opening.
 */
async function blockWebSockets(page: Page): Promise<void> {
  await page.addInitScript(() => {
    class RefusedSocket extends EventTarget {
      static readonly CONNECTING = 0
      static readonly OPEN = 1
      static readonly CLOSING = 2
      static readonly CLOSED = 3
      readyState = 0
      binaryType = 'blob'
      onopen: ((event: Event) => void) | null = null
      onmessage: ((event: Event) => void) | null = null
      onerror: ((event: Event) => void) | null = null
      onclose: ((event: Event) => void) | null = null
      constructor() {
        super()
        setTimeout(() => {
          this.readyState = 3
          const failed = new Event('error')
          this.onerror?.(failed)
          this.dispatchEvent(failed)
          const closed = new CloseEvent('close', { code: 1006 })
          this.onclose?.(closed)
          this.dispatchEvent(closed)
        }, 50)
      }
      send(): void {}
      close(): void {}
    }
    ;(window as unknown as { WebSocket: unknown }).WebSocket = RefusedSocket
  })
}

test('where WebSockets are blocked, Chat reads its mailbox on a timer and says so', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('nosocketchat', PASSWORD))
  const page = await context.newPage()
  await blockWebSockets(page)
  await page.goto(appUrl('chat'))
  await expect(page.getByTestId('chat-connection-polling')).toBeVisible({ timeout: 120_000 })
  await expect(page.getByText('Live connection blocked on this network')).toBeVisible()
  // It is not the "reconnecting" notice, and it does not flip back to it.
  await page.waitForTimeout(8_000)
  await expect(page.getByTestId('chat-connection-polling')).toBeVisible()
  await expect(page.getByText('Reconnecting…')).toHaveCount(0)
  await context.close()
})

test('where WebSockets are blocked, a note opens read-only with the reason', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  await registerAccount(context, newAccount('nosocketnote', PASSWORD))
  const page = await context.newPage()
  await page.goto(appUrl('office'))
  await page.getByTestId('office-new-note').click()
  await page.waitForURL((url) => url.origin === appOrigin('drive') && url.pathname.startsWith('/file/'), { timeout: 60_000 })
  await expect(page.getByRole('link', { name: 'Back to Office' })).toBeVisible({ timeout: 120_000 })
  const editor = page.url()
  // With the socket, it is an ordinary editable note.
  await expect(page.getByTestId('editor-live-blocked')).toHaveCount(0)

  const blocked = await context.newPage()
  await blockWebSockets(blocked)
  await blocked.goto(editor)
  await expect(blocked.getByTestId('editor-live-blocked')).toBeVisible({ timeout: 120_000 })
  await expect(blocked.getByText('This network blocks live editing.')).toBeVisible()
  await expect(blocked.getByTestId('editor-live-blocked').getByRole('button', { name: 'Download' })).toBeVisible()
  // The note is still there to read, and cannot be typed into.
  await expect(blocked.getByText('Untitled note').first()).toBeVisible()
  await expect(blocked.locator('.cm-content').first()).toHaveAttribute('contenteditable', 'false')
  await context.close()
})
