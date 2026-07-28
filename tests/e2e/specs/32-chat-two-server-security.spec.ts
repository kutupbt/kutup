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

async function requireResponseOrUiError(
  page: Page,
  response: Promise<import('@playwright/test').Response>,
): Promise<import('@playwright/test').Response> {
  const uiError = page.locator('[data-sonner-toast][data-type="error"]')
  const errorText = uiError.waitFor({ state: 'visible', timeout: 15_000 })
    .then(async () => (await uiError.textContent())?.trim() || 'unknown error')
    .catch(() => undefined)
  const first = await Promise.race([
    response.then(value => ({ kind: 'response' as const, value })),
    errorText.then(value => ({ kind: 'error' as const, value })),
  ])
  if (first.kind === 'error') {
    throw new Error(`browser operation failed: ${first.value ?? 'unknown error'}`)
  }
  // The orderer acknowledgement precedes the initiating client's durable
  // OpenMLS merge. Keep observing the UI briefly so a post-ack cryptographic
  // or state failure cannot be mistaken for a successful operation.
  const lateError = await Promise.race([
    errorText,
    page.waitForTimeout(1_000).then(() => undefined),
  ])
  if (lateError) throw new Error(`browser operation failed: ${lateError}`)
  return first.value
}

function bubble(page: Page, text: string) {
  return page.getByRole('main').getByText(text, { exact: true })
}

test.describe('two-server secure chat', () => {
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

  test('manages a federated MLS group and exchanges anonymous durable messages', async ({ browser, baseURL }) => {
    test.slow()
    if (!baseURL || !SECONDARY) throw new Error('two-server base URLs are required')
    const contextA = await browser.newContext({ baseURL })
    const contextB = await browser.newContext({ baseURL: SECONDARY })
    const contextC = await browser.newContext({ baseURL })
    const contextD = await browser.newContext({ baseURL: SECONDARY })
    const tag = Date.now() % 1_000_000
    const alice = `mlsalice${tag}`
    const bob = `mlsbob${tag}`
    const charlie = `mlscarol${tag}`
    const dave = `mlsdave${tag}`
    const aliceEmail = `${alice}@example.test`
    const bobEmail = `${bob}@example.test`
    const charlieEmail = `${charlie}@example.test`
    const daveEmail = `${dave}@example.test`

    await register(contextA, aliceEmail, alice)
    await register(contextB, bobEmail, bob)
    await register(contextC, charlieEmail, charlie)
    await register(contextD, daveEmail, dave)
    const pageA = await login(contextA, aliceEmail)
    const pageB = await login(contextB, bobEmail)
    const pageC = await login(contextC, charlieEmail)
    const pageD = await login(contextD, daveEmail)
    await openChat(pageA)
    await openChat(pageB)
    await openChat(pageC)
    await openChat(pageD)

    const genesisResponse = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/conversations'
    })
    const identifiedPackages = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/key-packages/identified'
    })
    const membershipCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-create-group').click()
    await pageA.getByTestId('chat-group-initial-member').fill(`${bob}@b.test`)
    await pageA.getByTestId('chat-group-create-submit').click()
    const genesis = await genesisResponse
    expect(genesis.ok()).toBe(true)
    const { conversationId } = await genesis.json() as { conversationId: string }
    expect(conversationId).toMatch(/^[0-9a-f-]{36}$/)
    const identifiedPackageResponse = await identifiedPackages
    expect(identifiedPackageResponse.ok()).toBe(true)
    const identifiedPackageRequest = identifiedPackageResponse.request().postDataJSON()
    expect((await membershipCommit).ok()).toBe(true)
    await expect(pageA.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })

    // No manual Sync action: the destination server sends only a generic
    // DrainMailbox WebSocket hint after committing the federated Welcome.
    await expect(pageB.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    const invitationAcceptance = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/invitations'
    })
    await pageB.getByTestId('chat-group-accept').click()
    const invitationAcceptanceResponse = await invitationAcceptance
    expect(invitationAcceptanceResponse.ok()).toBe(true)
    await expect(pageB.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })

    // Membership alone must not authorize first-contact package claims. This
    // protects local and remote users from package exhaustion by non-admins.
    const bobAuthorization = await invitationAcceptanceResponse.request().headerValue('authorization')
    expect(bobAuthorization).toMatch(/^Bearer /)
    const unauthorizedClaimStatus = await pageB.evaluate(
      async ({ authorization, request }) => {
        const response = await fetch('/api/chat/mls/key-packages/identified', {
          method: 'POST',
          headers: {
            Authorization: authorization!,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(request),
        })
        return response.status
      },
      { authorization: bobAuthorization, request: identifiedPackageRequest },
    )
    expect(unauthorizedClaimStatus).toBe(403)

    // Routine administrator changes use the same encrypted roster transition,
    // but preserve member count and routing domains and require no owner vote.
    const administratorCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-members').click()
    const bobOnAlice = pageA.getByTestId(`chat-group-member-${bob}@b.test`)
    await bobOnAlice.getByRole('button', {
      name: `Make administrator ${bob}@b.test`,
    }).click()
    expect((await requireResponseOrUiError(pageA, administratorCommit)).ok()).toBe(true)
    await expect(bobOnAlice.getByText('Administrator', { exact: true })).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    await pageB.getByTestId('chat-group-members').click()
    await expect(
      pageB.getByTestId(`chat-group-member-${bob}@b.test`)
        .getByText('Administrator', { exact: true }),
    ).toBeVisible({ timeout: 90_000 })
    await pageB.keyboard.press('Escape')

    const administratorAddCommit = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-add-member').click()
    await pageB.getByLabel('Group member address').fill(`${charlie}@a.test`)
    await pageB.getByRole('button', { name: 'Invite member' }).click()
    expect((await requireResponseOrUiError(pageB, administratorAddCommit)).ok()).toBe(true)
    await expect(pageC.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    await pageC.getByTestId('chat-group-accept').click()
    await expect(pageC.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })

    await pageA.getByTestId('chat-group-members').click()
    await expect(
      pageA.getByTestId(`chat-group-member-${charlie}@a.test`),
    ).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')
    await expect(
      pageA.getByRole('heading', { name: 'MLS group members' }),
    ).toBeHidden()

    // A rejected cross-server Welcome produces durable, federation-authenticated
    // advisory feedback. It cannot mutate the MLS roster: Alice must see the
    // exact member warning and manually commit the cryptographic removal.
    const rejectedMemberAddCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-add-member').click()
    await pageA.getByLabel('Group member address').fill(`${dave}@b.test`)
    await pageA.getByRole('button', { name: 'Invite member' }).click()
    const rejectedMemberAddResponse =
      await requireResponseOrUiError(pageA, rejectedMemberAddCommit)
    expect(rejectedMemberAddResponse.ok()).toBe(true)
    const aliceAuthorization =
      await rejectedMemberAddResponse.request().headerValue('authorization')
    expect(aliceAuthorization).toMatch(/^Bearer /)
    await expect(pageD.getByTestId('chat-group-invitations')).toBeVisible({ timeout: 90_000 })
    const invitationRejection = pageD.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/invitations'
    })
    await pageD.getByRole('button', { name: 'Reject' }).click()
    expect((await invitationRejection).ok()).toBe(true)
    await expect(pageD.getByTestId('chat-group-invitations')).toHaveCount(0)

    await expect.poll(
      () => pageA.evaluate(async ({ authorization, groupId, member }) => {
        const response = await fetch('/api/chat/mls/invitation-feedback', {
          headers: { Authorization: authorization! },
        })
        if (!response.ok) return false
        const feedback = await response.json() as Array<{
          conversationId: string
          member: { username: string; server?: string }
          decision: string
        }>
        return feedback.some(entry =>
          entry.conversationId === groupId
          && `${entry.member.username}@${entry.member.server}` === member
          && entry.decision === 'rejected')
      }, {
        authorization: aliceAuthorization,
        groupId: conversationId,
        member: `${dave}@b.test`,
      }),
      { timeout: 90_000 },
    ).toBe(true)

    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()
    await pageA.getByTestId('chat-group-members').click()
    await expect(
      pageA.getByTestId(`chat-group-invitation-feedback-${dave}@b.test`),
    ).toContainText('Rejected the invitation', { timeout: 90_000 })
    const rejectedMemberRemoveCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByRole('button', {
      name: `Remove ${dave}@b.test from group`,
    }).click()
    expect((await requireResponseOrUiError(pageA, rejectedMemberRemoveCommit)).ok()).toBe(true)
    await expect(
      pageA.getByTestId(`chat-group-member-${dave}@b.test`),
    ).toHaveCount(0, { timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    // Promote Bob while the current owner set is Alice-only (q=1), then prove
    // the resulting two-owner set (q=2) cannot remove Bob until his exact
    // encrypted manual approval returns. Both clients restart with the
    // partially approved transition/request still durable.
    const promoteOwnerCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId(`chat-group-owner-${bob}@b.test`).click()
    expect((await requireResponseOrUiError(pageA, promoteOwnerCommit)).ok()).toBe(true)
    await expect(
      pageA.getByTestId(`chat-group-member-owner-${bob}@b.test`),
    ).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    await pageB.getByTestId('chat-group-members').click()
    await expect(
      pageB.getByTestId(`chat-group-member-owner-${bob}@b.test`),
    ).toBeVisible({ timeout: 90_000 })
    await pageB.keyboard.press('Escape')

    let ownerRemovalControlSubmitted = false
    let awaitingOwnerRemovalApproval = true
    pageA.on('request', (request) => {
      if (
        awaitingOwnerRemovalApproval
        && request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/chat/mls/control/blocks'
      ) ownerRemovalControlSubmitted = true
    })
    const ownerApprovalRequest = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId(`chat-group-owner-${bob}@b.test`).click()
    expect((await requireResponseOrUiError(pageA, ownerApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(ownerRemovalControlSubmitted).toBe(false)

    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByTestId('chat-group-owner-approval')).toBeVisible({ timeout: 90_000 })
    await pageB.reload()
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByTestId('chat-group-owner-approval')).toBeVisible({ timeout: 90_000 })

    const ownerApprovalResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const removeOwnerCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, ownerApprovalResponse)).ok()).toBe(true)
    awaitingOwnerRemovalApproval = false
    expect((await requireResponseOrUiError(pageA, removeOwnerCommit)).ok()).toBe(true)
    await pageB.keyboard.press('Escape')

    await pageA.getByTestId('chat-group-members').click()
    await expect(
      pageA.getByTestId(`chat-group-member-owner-${bob}@b.test`),
    ).toHaveCount(0, { timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    // The owner changes ordering authorities through one owner-approved MLS
    // Commit and joint old/new quorums. Removing b.test still delivers the
    // exact Commit to Bob because participant routing is independent from the
    // ordering set.
    const removeAuthorityCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId('chat-group-authority-domains').fill('a.test')
    await pageA.getByTestId('chat-group-save-authorities').click()
    expect((await requireResponseOrUiError(pageA, removeAuthorityCommit)).ok()).toBe(true)
    await expect(pageA.getByTestId('chat-group-authority-a.test')).toBeVisible({ timeout: 90_000 })
    await expect(pageA.getByTestId('chat-group-authority-b.test')).toHaveCount(0)
    await pageA.keyboard.press('Escape')

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByTestId('chat-group-authority-a.test')).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByTestId('chat-group-authority-b.test')).toHaveCount(0)
    await pageB.keyboard.press('Escape')

    // Adding b.test back exercises exact history bootstrap before b.test may
    // contribute its new-set vote. Both participant clients then pin sequence 3.
    const addAuthorityCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId('chat-group-authority-domains').fill('a.test, b.test')
    await pageA.getByTestId('chat-group-save-authorities').click()
    expect((await requireResponseOrUiError(pageA, addAuthorityCommit)).ok()).toBe(true)
    await expect(pageA.getByTestId('chat-group-authority-b.test')).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByTestId('chat-group-authority-b.test')).toBeVisible({ timeout: 90_000 })
    await pageB.keyboard.press('Escape')

    const destinationMailbox: Array<Record<string, unknown>> = []
    pageB.on('response', (response) => {
      const url = new URL(response.url())
      if (
        response.request().method() !== 'GET'
        || !/^\/api\/chat\/mls\/messages\/\d+$/.test(url.pathname)
        || !response.ok()
      ) return
      void response.json()
        .then((body: { envelopes?: Array<Record<string, unknown>> }) => {
          destinationMailbox.push(...(body.envelopes ?? []))
        })
        .catch(() => {})
    })

    await expect(pageA.locator('[data-sonner-toast][data-type="error"]')).toHaveCount(0)

    const sentToBob = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const fromAlice = `mls-from-alice-${tag}`
    await send(pageA, fromAlice)
    expect((await requireResponseOrUiError(pageA, sentToBob)).ok()).toBe(true)
    await expect(bubble(pageB, fromAlice)).toBeVisible({ timeout: 90_000 })
    await expect.poll(
      () => destinationMailbox.some(envelope => envelope.deliveryKind === 'anonymous'),
      { timeout: 45_000 },
    ).toBe(true)
    const anonymous = destinationMailbox.find(envelope => envelope.deliveryKind === 'anonymous')
    expect(anonymous).not.toHaveProperty('conversationId')
    expect(anonymous).not.toHaveProperty('incarnation')

    const sentToAlice = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const fromBob = `mls-from-bob-${tag}`
    await send(pageB, fromBob)
    expect((await requireResponseOrUiError(pageB, sentToAlice)).ok()).toBe(true)
    await expect(bubble(pageA, fromBob)).toBeVisible({ timeout: 90_000 })

    await pageB.reload()
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByTestId(`chat-group-${conversationId}`)).toBeVisible({ timeout: 90_000 })
    await expect(bubble(pageB, fromAlice)).toBeVisible({ timeout: 90_000 })
    await expect(bubble(pageB, fromBob)).toBeVisible({ timeout: 90_000 })

    // Re-promoting the previously demoted owner reuses the exact durable
    // group-scoped candidate key. The resulting q=2 owner set first proves
    // restart-safe incarnation recovery without an ordering vote, then closes
    // the recovered incarnation through the ordinary control quorum.
    const repromoteOwnerCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId(`chat-group-owner-${bob}@b.test`).click()
    expect((await requireResponseOrUiError(pageA, repromoteOwnerCommit)).ok()).toBe(true)
    await expect(
      pageA.getByTestId(`chat-group-member-owner-${bob}@b.test`),
    ).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    await pageB.getByTestId('chat-group-members').click()
    await expect(
      pageB.getByTestId(`chat-group-member-owner-${bob}@b.test`),
    ).toBeVisible({ timeout: 90_000 })
    await pageB.keyboard.press('Escape')

    // Private group policy uses the same exact owner-only approval exchange.
    // The policy value stays in MLS; ordering sees only an unchanged-roster
    // transition. Restart both owners before approval to prove durable resume.
    let senderPolicyControlSubmitted = false
    let awaitingSenderPolicyApproval = true
    pageA.on('request', (request) => {
      if (
        awaitingSenderPolicyApproval
        && request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/chat/mls/control/blocks'
      ) senderPolicyControlSubmitted = true
    })
    const senderPolicyApprovalRequest = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId('chat-group-senders-administrators').click()
    expect((await requireResponseOrUiError(pageA, senderPolicyApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(senderPolicyControlSubmitted).toBe(false)
    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve who may send messages?')).toBeVisible({ timeout: 90_000 })
    await pageB.reload()
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve who may send messages?')).toBeVisible({ timeout: 90_000 })

    const senderPolicyApprovalResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const senderPolicyCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, senderPolicyApprovalResponse)).ok()).toBe(true)
    awaitingSenderPolicyApproval = false
    expect((await requireResponseOrUiError(pageA, senderPolicyCommit)).ok()).toBe(true)
    await pageB.keyboard.press('Escape')

    await pageA.getByTestId('chat-group-members').click()
    await expect(pageA.getByTestId('chat-group-senders-administrators')).toBeDisabled({
      timeout: 90_000,
    })
    await pageA.keyboard.press('Escape')
    // The orderer acknowledgement only proves that Alice finalized the block.
    // Wait until the remote owner has independently applied that epoch and
    // published its epoch-bound delivery capability before sending the next
    // owner-approval request.
    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByTestId('chat-group-senders-administrators')).toBeDisabled({
      timeout: 90_000,
    })
    await pageB.keyboard.press('Escape')
    await pageC.getByTestId(`chat-group-${conversationId}`).click()
    await expect(
      pageC.getByPlaceholder('Only group administrators may send messages'),
    ).toBeDisabled({ timeout: 90_000 })

    // V1 cryptographic policy is monotonic: owners may tighten the canonical
    // application plaintext ceiling but cannot alter suite/padding/delivery.
    const cryptographicPolicyApprovalRequest = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    await pageA.getByTestId('chat-group-members').click()
    await pageA.getByTestId('chat-group-maximum-plaintext').fill('1024')
    await pageA.getByTestId('chat-group-tighten-plaintext').click()
    expect((await requireResponseOrUiError(pageA, cryptographicPolicyApprovalRequest)).ok()).toBe(true)
    await pageA.keyboard.press('Escape')

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve stricter MLS message limits?')).toBeVisible({
      timeout: 90_000,
    })
    const cryptographicPolicyApprovalResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const cryptographicPolicyCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, cryptographicPolicyApprovalResponse)).ok()).toBe(true)
    expect((await requireResponseOrUiError(pageA, cryptographicPolicyCommit)).ok()).toBe(true)
    await pageB.keyboard.press('Escape')

    await pageA.getByTestId('chat-group-members').click()
    await expect(pageA.getByTestId('chat-group-maximum-plaintext')).toHaveValue('1024', {
      timeout: 90_000,
    })
    await pageA.keyboard.press('Escape')
    let oversizedSubmitted = false
    const observeOversized = (request: import('@playwright/test').Request) => {
      if (
        request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/chat/mls/anonymous/messages'
      ) oversizedSubmitted = true
    }
    pageA.on('request', observeOversized)
    await send(pageA, 'x'.repeat(2048))
    await expect(pageA.locator('[data-sonner-toast][data-type="error"]')).toBeVisible({
      timeout: 15_000,
    })
    await pageA.waitForTimeout(1_000)
    expect(oversizedSubmitted).toBe(false)
    pageA.off('request', observeOversized)
    await expect(pageA.locator('[data-sonner-toast][data-type="error"]')).toHaveCount(0, {
      timeout: 15_000,
    })

    // Group-control traffic remains available under administrator-only
    // application policy. Bob removes the non-administrator before recovery.
    const administratorRemoveCommit = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-members').click()
    await pageB.getByRole('button', {
      name: `Remove ${charlie}@a.test from group`,
    }).click()
    expect((await requireResponseOrUiError(pageB, administratorRemoveCommit)).ok()).toBe(true)
    await expect(
      pageB.getByTestId(`chat-group-member-${charlie}@a.test`),
    ).toHaveCount(0, { timeout: 90_000 })
    await pageB.keyboard.press('Escape')

    await pageA.getByTestId('chat-group-members').click()
    await expect(
      pageA.getByTestId(`chat-group-member-${charlie}@a.test`),
    ).toHaveCount(0, { timeout: 90_000 })
    await pageA.keyboard.press('Escape')

    let recoverySubmitted = false
    let awaitingRecoveryApproval = true
    pageA.on('request', (request) => {
      if (
        awaitingRecoveryApproval
        && request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/chat/mls/conversations/recover'
      ) recoverySubmitted = true
    })
    const recoveryApprovalRequest = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    await pageA.getByTestId('chat-group-members').click()
    pageA.once('dialog', dialog => void dialog.accept())
    await pageA.getByTestId('chat-group-recover').click()
    expect((await requireResponseOrUiError(pageA, recoveryApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(recoverySubmitted).toBe(false)

    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve MLS group recovery?')).toBeVisible({ timeout: 90_000 })
    await pageB.reload()
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve MLS group recovery?')).toBeVisible({ timeout: 90_000 })

    const recoveryApprovalResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const recoveryCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/conversations/recover'
    })
    const destinationRecoveryEvidence = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'GET'
        && path === `/api/chat/mls/conversations/${conversationId}/2/recovery`
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, recoveryApprovalResponse)).ok()).toBe(true)
    awaitingRecoveryApproval = false
    const recoveryResponse = await requireResponseOrUiError(pageA, recoveryCommit)
    expect(recoveryResponse.ok()).toBe(true)
    expect(await recoveryResponse.json()).toMatchObject({
      conversationId,
      previousIncarnation: 1,
      incarnation: 2,
      status: 'active',
    })
    expect((await destinationRecoveryEvidence).ok()).toBe(true)
    await pageB.keyboard.press('Escape')

    const afterRecoverySend = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const afterRecovery = `mls-after-recovery-${tag}`
    await send(pageA, afterRecovery)
    expect((await requireResponseOrUiError(pageA, afterRecoverySend)).ok()).toBe(true)
    await expect(bubble(pageB, afterRecovery)).toBeVisible({ timeout: 90_000 })

    await pageA.reload()
    await pageB.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await expect(bubble(pageA, afterRecovery)).toBeVisible({ timeout: 90_000 })
    await expect(bubble(pageB, afterRecovery)).toBeVisible({ timeout: 90_000 })

    let closeControlSubmitted = false
    let awaitingCloseApproval = true
    pageA.on('request', (request) => {
      if (
        awaitingCloseApproval
        && request.method() === 'POST'
        && new URL(request.url()).pathname === '/api/chat/mls/control/blocks'
      ) closeControlSubmitted = true
    })
    const closeApprovalRequest = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    await pageA.getByTestId('chat-group-members').click()
    pageA.once('dialog', dialog => void dialog.accept())
    await pageA.getByTestId('chat-group-close').click()
    expect((await requireResponseOrUiError(pageA, closeApprovalRequest)).ok()).toBe(true)
    await pageA.waitForTimeout(1_000)
    expect(closeControlSubmitted).toBe(false)

    await pageA.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()

    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve closing this MLS group?')).toBeVisible({ timeout: 90_000 })
    await pageB.reload()
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId('chat-group-members').click()
    await expect(pageB.getByText('Approve closing this MLS group?')).toBeVisible({ timeout: 90_000 })

    const closeApprovalResponse = pageB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/anonymous/messages'
    })
    const closeCommit = pageA.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'POST'
        && path === '/api/chat/mls/control/blocks'
    })
    await pageB.getByTestId('chat-group-owner-approve').click()
    expect((await requireResponseOrUiError(pageB, closeApprovalResponse)).ok()).toBe(true)
    awaitingCloseApproval = false
    expect((await requireResponseOrUiError(pageA, closeCommit)).ok()).toBe(true)

    await expect(pageA.getByPlaceholder('This MLS group is closed')).toBeDisabled({
      timeout: 90_000,
    })
    await pageA.getByTestId('chat-group-members').click()
    await expect(pageA.getByTestId('chat-group-closed')).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByTestId('chat-group-closed')).toBeVisible({ timeout: 90_000 })
    await pageA.keyboard.press('Escape')
    await pageB.keyboard.press('Escape')
    await expect(pageA.getByPlaceholder('This MLS group is closed')).toBeDisabled()
    await expect(pageB.getByPlaceholder('This MLS group is closed')).toBeDisabled()

    await pageA.reload()
    await pageB.reload()
    await expect(pageA.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await expect(pageB.getByRole('heading', { name: 'Messages' })).toBeVisible({ timeout: 90_000 })
    await pageA.getByTestId(`chat-group-${conversationId}`).click()
    await pageB.getByTestId(`chat-group-${conversationId}`).click()
    await expect(pageA.getByPlaceholder('This MLS group is closed')).toBeDisabled()
    await expect(pageB.getByPlaceholder('This MLS group is closed')).toBeDisabled()

    await contextA.close()
    await contextB.close()
    await contextC.close()
    await contextD.close()
  })
})
