import { expect, test, type BrowserContext, type Page } from '@playwright/test'

const SECONDARY = process.env.E2E_SECONDARY_BASE_URL
const PASSWORD = 'Deneme123*FederatedSecurityPassword'

async function captureMnemonic(page: Page): Promise<string> {
  const allText = await page.evaluate(() => document.body.innerText)
  const seen = new Map<number, string>()
  for (const match of allText.matchAll(/(?:^|\s)(\d{1,2})[.)]\s*([a-z]+)\b/gim)) {
    const index = Number(match[1])
    if (index >= 1 && index <= 24 && !seen.has(index)) seen.set(index, match[2])
  }
  const words = Array.from({ length: 24 }, (_, index) => seen.get(index + 1))
  if (words.some((word) => !word)) throw new Error('failed to capture recovery mnemonic')
  return words.join(' ')
}

async function register(context: BrowserContext, email: string, username: string): Promise<void> {
  const page = await context.newPage()
  await page.goto('/register')
  await page.locator('input[type=email]').fill(email)
  await page.getByLabel(/username/i).fill(username)
  const passwords = page.locator('input[type=password]')
  await passwords.nth(0).fill(PASSWORD)
  await passwords.nth(1).fill(PASSWORD)
  await page.locator('button[type=submit]').click()
  await expect(page.getByText(/once/i).first()).toBeVisible({ timeout: 30_000 })
  const mnemonic = await captureMnemonic(page)
  await page.getByRole('button', { name: /saved/i }).click()
  await page.locator('textarea').fill(mnemonic)
  await page.locator('button[type=submit]').click()
  await expect(page.getByRole('button', { name: /sign ?in/i })).toBeVisible({ timeout: 30_000 })
  await page.close()
}

async function login(context: BrowserContext, email: string): Promise<Page> {
  const page = await context.newPage()
  await page.goto('/login')
  await page.locator('input[type=email]').fill(email)
  await page.locator('input[type=password]').fill(PASSWORD)
  await page.locator('button[type=submit]').click()
  await page.waitForURL(/\/drive/, { timeout: 30_000 })
  return page
}

async function openChat(page: Page): Promise<void> {
  await page.goto('/chat')
  await expect(page.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
  await expect(page.getByText(/End-to-end encrypted · device \d+/)).toBeVisible({ timeout: 90_000 })
}

async function send(page: Page, text: string): Promise<void> {
  await page.locator('main form input').fill(text)
  await page.getByRole('button', { name: 'Send' }).click()
}

function bubble(page: Page, text: string) {
  return page.getByRole('main').getByText(text, { exact: true })
}

test.describe('two-server transparency and sealed sender', () => {
  test.skip(!SECONDARY, 'set E2E_SECONDARY_BASE_URL for the isolated federation topology')

  test('pins remote policy, establishes sealed delivery, rotates capability, and never falls back', async ({ browser, baseURL }) => {
    test.slow()
    if (!baseURL || !SECONDARY) throw new Error('two-server base URLs are required')
    const contextA = await browser.newContext({ baseURL })
    const contextB = await browser.newContext({ baseURL: SECONDARY })
    const tag = Date.now() % 1_000_000
    const alice = `sealalice${tag}`
    const bob = `sealbob${tag}`
    const aliceEmail = `${alice}@example.test`
    const bobEmail = `${bob}@example.test`

    await register(contextA, aliceEmail, alice)
    await register(contextB, bobEmail, bob)
    const pageA = await login(contextA, aliceEmail)
    const pageB = await login(contextB, bobEmail)
    await openChat(pageA)
    await openChat(pageB)

    const identifiedToBob: string[] = []
    pageA.on('request', (request) => {
      const path = new URL(request.url()).pathname
      if (request.method() === 'POST' && path.includes('/api/chat/users/') && path.endsWith('/messages')) {
        identifiedToBob.push(path)
      }
    })

    await pageA.getByPlaceholder('Username').fill(`${bob}@b.test`)
    await pageA.getByRole('button', { name: 'Start chat' }).click()
    const firstIdentified = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST' && path.includes('/api/chat/users/') && path.endsWith('/messages')
    })
    const first = `identified-first-${tag}`
    await send(pageA, first)
    expect((await firstIdentified).ok()).toBe(true)
    await expect(pageB.getByText('1 message request')).toBeVisible({ timeout: 45_000 })
    await pageB.getByRole('button', { name: new RegExp(alice) }).click()
    await expect(bubble(pageB, first)).toBeVisible()
    await pageB.getByRole('button', { name: 'Accept', exact: true }).click()

    const sealedReplyResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path.includes('/api/chat/anonymous/users/')
        && path.endsWith('/messages')
    })
    const reply = `sealed-reply-${tag}`
    await send(pageB, reply)
    expect((await sealedReplyResponse).ok()).toBe(true)
    await expect(bubble(pageA, reply)).toBeVisible({ timeout: 45_000 })

    // Selecting the remote peer triggers the shared engine's independent
    // policy/checkpoint verification. The dialog exposes exact policy material.
    await pageA.getByLabel('Transparency details').click()
    const details = pageA.getByRole('dialog')
    await expect(details.getByText('b.test', { exact: true })).toBeVisible({ timeout: 30_000 })
    await expect(details.getByText('Required quorum')).toBeVisible()
    await expect(details.getByText('1', { exact: true }).first()).toBeVisible()
    await pageA.keyboard.press('Escape')

    const destinationEnvelopes: Array<Record<string, unknown>> = []
    pageB.on('response', (response) => {
      const url = new URL(response.url())
      if (response.request().method() !== 'GET' || url.pathname !== '/api/chat/messages' || !response.ok()) return
      void response.json()
        .then((body: { envelopes?: Array<Record<string, unknown>> }) => {
          destinationEnvelopes.push(...(body.envelopes ?? []))
        })
        .catch(() => {})
    })
    identifiedToBob.length = 0
    const sealedSendResponse = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path.includes('/api/chat/anonymous/users/')
        && path.endsWith('/messages')
    })
    const sealed = `sealed-second-${tag}`
    await send(pageA, sealed)
    expect((await sealedSendResponse).ok()).toBe(true)
    await pageB.getByRole('button', { name: 'Sync messages' }).click()
    await expect.poll(
      () => destinationEnvelopes.some((envelope) => envelope.sealedSender === true),
      { timeout: 45_000 },
    ).toBe(true)
    const destinationEnvelope = destinationEnvelopes.find((envelope) => envelope.sealedSender === true)
    expect(destinationEnvelope).not.toHaveProperty('sender')
    expect(destinationEnvelope?.senderDeviceId).toBe(0)
    await expect(bubble(pageB, sealed)).toBeVisible({ timeout: 45_000 })
    expect(identifiedToBob).toEqual([])

    // Blocking publishes the new profile key/capability before returning.
    // Alice's stolen/stale capability receives the uniform 404 and the
    // established conversation must not attempt the identified endpoint.
    await pageB.getByRole('button', { name: 'Block', exact: true }).click()
    await expect(pageB.getByRole('button', { name: 'Unblock', exact: true })).toBeVisible({
      timeout: 45_000,
    })
    identifiedToBob.length = 0
    const rejectedAnonymous = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path.includes('/api/chat/anonymous/users/')
        && (path.endsWith('/keys') || path.endsWith('/messages'))
        && response.status() === 404
    })
    await send(pageA, `rejected-stale-capability-${tag}`)
    await rejectedAnonymous
    await pageA.waitForTimeout(1_000)
    expect(identifiedToBob).toEqual([])
    await expect(bubble(pageB, `rejected-stale-capability-${tag}`)).toHaveCount(0)

    await contextA.close()
    await contextB.close()
  })
})
