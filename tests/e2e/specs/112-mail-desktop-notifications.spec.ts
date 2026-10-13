import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'

// Desktop notifications (docs/plans/mail-parity.md, P6), as Proton's: new
// unread mail in the Inbox shows "New email received" with its sender and
// subject while Mail is open, and opens when clicked; Settings shows the
// browser's permission and sends a test; a banner asks once.

const PASSWORD = 'Deneme123*MailNotificationsPassword'

type Shown = { title: string; body: string; onclick: (() => void) | null }

/** The browser's notifications, recorded instead of shown; `permission` as given. */
async function recordNotifications(context: BrowserContext, permission: NotificationPermission) {
  await context.addInitScript((start: NotificationPermission) => {
    const shown: Shown[] = []
    let current = start
    class Recorded {
      static get permission() {
        return current
      }
      static requestPermission() {
        current = 'granted'
        return Promise.resolve(current)
      }
      title: string
      body: string
      onclick: (() => void) | null = null
      constructor(title: string, options?: NotificationOptions) {
        this.title = title
        this.body = options?.body ?? ''
        shown.push(this)
      }
      close() {}
    }
    Object.defineProperty(window, 'Notification', { value: Recorded, configurable: true })
    Object.defineProperty(window, '__shown', { value: shown })
  }, permission)
}

const shown = (page: Page) => page.evaluate(() => (window as unknown as { __shown: Shown[] }).__shown.map(({ title, body }) => ({ title, body })))

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('desktop notifications: new mail, a click opens it; settings and the banner', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('dnalice', PASSWORD)
  const bob = newAccount('dnbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  await recordNotifications(aliceContext, 'granted')
  await recordNotifications(bobContext, 'default')
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)

  // Bob has not answered yet: the banner asks; Enable asks the browser.
  const banner = bobMail.getByRole('region', { name: 'Desktop notifications' })
  await expect(banner).toBeVisible({ timeout: 30_000 })
  await banner.getByRole('button', { name: 'Enable desktop notifications' }).click()
  await expect(banner).toHaveCount(0)
  // Alice has: no banner.
  await expect(mail.getByRole('region', { name: 'Desktop notifications' })).toHaveCount(0)

  const subject = `Haber ${Date.now().toString(36)}`
  await bobMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = bobMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  await bobMail.getByRole('textbox', { name: 'Message' }).fill('merhaba')
  await bobMail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(bobMail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })

  // Told on Mail's next poll, once.
  await expect.poll(() => shown(mail), { timeout: 90_000, intervals: [2_000] }).toEqual([
    { title: 'New email received', body: `From: ${bob.username} - ${subject}` },
  ])
  // Clicking it opens the message.
  await mail.evaluate(() => (window as unknown as { __shown: Shown[] }).__shown[0].onclick?.())
  await expect(mail).toHaveURL(/\/inbox\/[0-9a-f-]+$/)
  await expect(mail.getByRole('heading', { name: subject })).toBeVisible({ timeout: 60_000 })

  // Settings: on, and a test.
  await mail.goto(appUrl('mail', '/settings/general'))
  await expect(mail.getByText('Desktop notifications are on')).toBeVisible({ timeout: 60_000 })
  await mail.getByRole('button', { name: 'Send test notification' }).click()
  await expect.poll(() => shown(mail)).toEqual([{ title: 'You have a new email', body: 'This is how new mail will look.' }])

  await aliceContext.close()
  await bobContext.close()
})
