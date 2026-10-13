import { expect, test, type BrowserContext, type Page, type Request } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { openWhenArrived } from '../fixtures/mail'

// Tracker protection (docs/plans/mail-parity.md, P5), as Proton's "Protect
// against email tracking": known tracking pixels are counted before anything
// loads and never load; links lose their tracking parameters; remote images
// come through the Kutup image proxy, and one it cannot get loads directly
// only when the reader asks.

const PASSWORD = 'Deneme123*MailImageProxyPassword'
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64')

async function openMail(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(appUrl('mail'))
  await expect(page.getByRole('heading', { name: 'Inbox' })).toBeVisible({ timeout: 120_000 })
  return page
}

test('tracker protection: trackers blocked, links cleaned, images through the proxy', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }
  const domain = settings.chat.serverName
  const alice = newAccount('ipalice', PASSWORD)
  const bob = newAccount('ipbob', PASSWORD)
  const aliceContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const bobContext = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  // What Alice's browser asks the outside world for.
  const tracked: string[] = []
  const direct: string[] = []
  await aliceContext.route(/^https:\/\/[^/]*list-manage\.com\//, (route) => {
    tracked.push(route.request().url())
    return route.abort()
  })
  await aliceContext.route(/^https:\/\/images\.example\.test\//, (route) => {
    direct.push(route.request().url())
    return route.fulfill({ contentType: 'image/png', body: PNG })
  })
  await bobContext.route(/list-manage\.com|images\.example\.test/, (route) => route.abort())
  await registerAccount(aliceContext, alice)
  await registerAccount(bobContext, bob)
  const mail = await openMail(aliceContext)
  const bobMail = await openMail(bobContext)
  const tag = Date.now().toString(36)
  const subject = `Bülten ${tag}`
  const tracker = `https://x.us1.list-manage.com/track/open.php?u=${tag}`
  const image = `https://images.example.test/logo-${tag}.png`

  // Tracker protection is on by default.
  await mail.goto(appUrl('mail', '/settings/general'))
  await expect(mail.getByRole('checkbox', { name: /Protect against email tracking/ })).toBeChecked({ timeout: 60_000 })
  await mail.goto(appUrl('mail'))

  await bobMail.getByRole('button', { name: 'New message' }).first().click()
  const composer = bobMail.getByRole('dialog', { name: 'New message' })
  await composer.getByRole('combobox', { name: 'To' }).fill(`${alice.username}@${domain}`)
  await composer.getByRole('combobox', { name: 'To' }).press('Enter')
  await composer.getByRole('textbox', { name: 'Subject' }).fill(subject)
  const editor = bobMail.getByRole('textbox', { name: 'Message' })
  await editor.click()
  // Pasted HTML, as a newsletter's.
  await editor.evaluate(
    (element, html) => {
      const data = new DataTransfer()
      data.setData('text/html', html)
      data.setData('text/plain', 'Bülten')
      element.dispatchEvent(new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true }))
    },
    `<p>Bülten</p><p><img src="${image}" alt="logo"><img src="${tracker}" alt=""></p><p><a href="https://shop.example.org/?id=${tag}&utm_source=news&fbclid=x">Mağaza</a></p>`,
  )
  await expect(editor.locator(`img[src="${image}"]`)).toHaveCount(1)
  await expect(editor.locator(`img[src="${tracker}"]`)).toHaveCount(1)
  await bobMail.getByRole('dialog', { name: subject }).getByRole('button', { name: 'Send', exact: true }).click()
  await expect(bobMail.getByRole('button', { name: /^Send(ing…)?$/ })).toHaveCount(0, { timeout: 60_000 })

  await openWhenArrived(mail, new RegExp(subject))
  const body = mail.frameLocator('iframe[title="Message"]').last()
  await expect(body.getByText('Bülten')).toBeVisible({ timeout: 60_000 })
  // Counted before anything loads; the link goes without its tracking.
  const summary = mail.getByRole('button', { name: '1 tracker blocked · 1 link cleaned' })
  await expect(summary).toBeVisible({ timeout: 30_000 })
  await expect(body.getByRole('link', { name: 'Mağaza' })).toHaveAttribute('href', `https://shop.example.org/?id=${tag}`)
  await summary.click()
  const details = mail.getByRole('dialog', { name: 'Email tracker protection' })
  await expect(details.getByRole('list', { name: 'Blocked trackers' }).getByText('Mailchimp')).toBeVisible()
  await expect(details.getByText('Removed: utm_source, fbclid')).toBeVisible()
  await details.getByRole('button', { name: 'Close', exact: true }).last().click()

  // Loading asks the proxy, never the tracker; the image it cannot get
  // loads directly only when Alice says so.
  const proxiedUrls: string[] = []
  // The address goes in the body, never in the URL.
  const asked = (r: Request) => (new URL(r.url()).pathname === '/api/mail/images' && r.method() === 'POST' ? ((r.postDataJSON() as { url?: string }).url ?? '') : null)
  mail.on('request', (r) => {
    const url = asked(r)
    if (url !== null) proxiedUrls.push(url)
  })
  const proxied = mail.waitForRequest((r) => asked(r) === image)
  await mail.getByRole('button', { name: 'Load images' }).click()
  await mail.getByRole('dialog', { name: 'Load remote images?' }).getByRole('button', { name: 'Load images' }).click()
  await proxied
  // The tracker is not even asked of the proxy.
  expect(proxiedUrls.some((url) => url.includes('list-manage'))).toBe(false)
  await expect(mail.getByText('Tracker protection prevented some images from loading. Load them if you trust the sender.')).toBeVisible({ timeout: 60_000 })
  expect(direct).toEqual([])
  await mail.getByRole('button', { name: 'Load', exact: true }).click()
  await expect(body.getByRole('img', { name: 'logo' })).toBeVisible({ timeout: 30_000 })
  await expect.poll(() => direct.length).toBeGreaterThan(0)
  expect(tracked).toEqual([])

  await aliceContext.close()
  await bobContext.close()
})
