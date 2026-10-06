// Meetings: calls anyone holding the link can join, with or without a Kutup
// account (docs/chat-calls.md, "Meetings"). Needs an SFU
// (`docker compose --profile sfu`), so these skip on a stack without one.

import { readFileSync } from 'node:fs'
import { expect, test, type Page } from '@playwright/test'
import { apiUrl, appUrl, newAccount, registerAccount } from '../fixtures/apps'
import { acceptRequest, message, openChat, openChats, openConversationWith, openDirectChat, send } from '../fixtures/chat'

const PASSWORD = 'Deneme123*MeetingsPassword'

function tile(page: Page, name: string) {
  return page.locator(`[data-testid="chat-group-call-tile"][data-name="${name}"]`)
}

function meeting(page: Page, title: string) {
  return page.locator(`[data-testid="chat-meeting"][data-title="${title}"]`)
}

async function join(page: Page, name: string, video: boolean): Promise<void> {
  await expect(page.getByTestId('chat-link-call-name')).toBeVisible({ timeout: 60_000 })
  await page.getByTestId('chat-link-call-name').fill(name)
  await page.getByTestId(video ? 'chat-link-call-join-video' : 'chat-link-call-join').click()
  await expect(page.getByTestId('chat-link-call-screen')).toHaveAttribute('data-phase', 'active', { timeout: 60_000 })
}

async function hostsMeetings(page: Page): Promise<boolean> {
  const settings = (await (await page.request.get(apiUrl('/auth/settings'))).json()) as { chat: { callLinks?: boolean } }
  return settings.chat.callLinks === true
}

test('someone without an account joins a scheduled meeting through its link', async ({ browser }) => {
  test.slow()
  const owner = newAccount('meetowner', PASSWORD)
  const ownerContext = await browser.newContext()
  await registerAccount(ownerContext, owner)
  const chat = await openChat(ownerContext)
  test.skip(!(await hostsMeetings(chat)), 'this stack has no SFU (docker compose --profile sfu)')

  // Schedule a meeting. What reaches the server is the room, a public
  // nonce, the hashes of the access and host tokens, the sealed details and
  // whether there is a waiting room: never the link, the title or the time.
  await chat.getByRole('link', { name: 'Meetings', exact: true }).click()
  await expect(chat.getByTestId('chat-meetings-empty')).toBeVisible({ timeout: 30_000 })
  await chat.getByTestId('chat-meeting-schedule').click()
  const title = `Team sync ${Date.now()}`
  await chat.getByTestId('chat-meeting-title').fill(title)
  await chat.getByTestId('chat-meeting-date').fill('2031-05-06')
  await chat.getByTestId('chat-meeting-time').fill('14:30')
  const registration = chat.waitForRequest((sent) => sent.method() === 'POST' && new URL(sent.url()).pathname === '/api/chat/call-links')
  await chat.getByTestId('chat-meeting-save').click()
  const registeredBody = (await registration).postData() ?? ''
  const registered = JSON.parse(registeredBody) as Record<string, unknown>
  expect(Object.keys(registered).sort()).toEqual(['accessTokenHash', 'hostTokenHash', 'info', 'nonce', 'roomId', 'waitingRoom'])
  expect(registered.waitingRoom).toBe(false)
  expect(registeredBody).not.toContain('Team sync')

  const row = chat.getByTestId('chat-meetings-upcoming').locator(`[data-testid="chat-meeting"][data-title="${title}"]`)
  await expect(row).toBeVisible({ timeout: 30_000 })
  await expect(row.getByTestId('chat-meeting-when')).toContainText('May 6')
  await expect(row.getByTestId('chat-meeting-when')).toContainText('60 minutes')
  const url = (await row.getByTestId('chat-meeting-url').textContent())!.trim()
  expect(url).toMatch(/\/call#[A-Za-z0-9_-]{44}$/)
  expect(registeredBody).not.toContain(url.split('#')[1])

  // Its calendar file names the time in UTC and carries the link.
  const download = chat.waitForEvent('download')
  await row.getByTestId('chat-meeting-ics').click()
  const file = await download
  expect(file.suggestedFilename()).toMatch(/^Team-sync-\d+\.ics$/)
  const ics = readFileSync((await file.path())!, 'utf8')
  expect(ics).toContain('BEGIN:VEVENT')
  expect(ics).toMatch(/DTSTART:20310506T\d{6}Z/)
  expect(ics.replace(/\r\n /g, '')).toContain(`URL:${url}`)

  // Another of the owner's sessions derives the same meeting from the account.
  await chat.reload()
  await expect(meeting(chat, title).getByTestId('chat-meeting-url')).toHaveText(url, { timeout: 120_000 })

  // A browser with no account at all opens the link and sees what it is.
  const guestContext = await browser.newContext()
  const guest = await guestContext.newPage()
  const requests: string[] = []
  guest.on('request', (sent) => requests.push(sent.url()))
  await guest.goto(url)
  await expect(guest.getByTestId('chat-link-call-title')).toHaveText(title, { timeout: 60_000 })
  await expect(guest.getByTestId('chat-link-call-when')).toContainText('May 6')
  await join(guest, 'Guest Gül', true)
  // The fragment never left the browser, and no sign-in was asked for.
  expect(requests.some((sent) => sent.includes(url.split('#')[1]))).toBe(false)
  expect(requests.some((sent) => /\/login|\/api\/auth\/forks/.test(sent))).toBe(false)

  // The owner joins from the list.
  const popup = ownerContext.waitForEvent('page')
  await meeting(chat, title).getByTestId('chat-meeting-join').click()
  const ownerCall = await popup
  await join(ownerCall, 'Owner Ada', false)

  // Each sees the other by the name they chose, under the meeting's title.
  await expect(tile(guest, 'Owner Ada')).toBeVisible({ timeout: 60_000 })
  await expect(tile(ownerCall, 'Guest Gül')).toBeVisible({ timeout: 60_000 })
  await expect(tile(ownerCall, 'Guest Gül')).toHaveAttribute('data-video', 'on', { timeout: 60_000 })
  await expect(guest.getByRole('heading', { name: title })).toBeVisible()
  await guest.getByTestId('chat-call-people-button').click()
  await expect(guest.getByTestId('chat-call-person')).toHaveCount(2)

  // The meeting's own chat: a message from the guest shows as unread on the
  // owner's side, then in the panel under the guest's name.
  await guest.getByTestId('chat-call-tab-chat').click()
  const text = `hello from the guest ${Date.now()}`
  await guest.getByTestId('chat-meeting-chat-input').fill(text)
  await guest.getByTestId('chat-meeting-chat-input').press('Enter')
  await expect(guest.getByTestId('chat-meeting-message').filter({ hasText: text })).toBeVisible({ timeout: 30_000 })
  await expect(ownerCall.getByTestId('chat-call-chat-unread')).toBeVisible({ timeout: 30_000 })
  await ownerCall.getByTestId('chat-call-chat-button').click()
  const received = ownerCall.getByTestId('chat-meeting-message').filter({ hasText: text })
  await expect(received).toBeVisible({ timeout: 30_000 })
  await expect(received).toContainText('Guest Gül')
  await expect(ownerCall.getByTestId('chat-call-chat-unread')).toHaveCount(0)
  await ownerCall.getByTestId('chat-meeting-chat-input').fill('welcome')
  await ownerCall.getByTestId('chat-meeting-chat-input').press('Enter')
  await expect(guest.getByTestId('chat-meeting-message').filter({ hasText: 'welcome' })).toContainText('Owner Ada', { timeout: 30_000 })
  await guest.getByTestId('chat-call-panel-close').click()
  await ownerCall.getByTestId('chat-call-panel-close').click()

  // The guest shares a screen; the owner sees it.
  await guest.getByTestId('chat-link-call-screen-share').click()
  await expect(ownerCall.getByTestId('chat-group-call-screen-tile')).toBeVisible({ timeout: 60_000 })
  await guest.getByTestId('chat-link-call-screen-share').click()
  await expect(ownerCall.getByTestId('chat-group-call-screen-tile')).toHaveCount(0, { timeout: 45_000 })

  // Leaving returns to the join form. Someone joining now sees no earlier chat.
  await guest.getByTestId('chat-link-call-leave').click()
  await expect(guest.getByTestId('chat-link-call-left')).toBeVisible({ timeout: 30_000 })
  await expect(tile(ownerCall, 'Guest Gül')).toHaveCount(0, { timeout: 45_000 })
  await guest.getByTestId('chat-link-call-join').click()
  await expect(guest.getByTestId('chat-link-call-screen')).toHaveAttribute('data-phase', 'active', { timeout: 60_000 })
  await guest.getByTestId('chat-call-chat-button').click()
  await expect(guest.getByTestId('chat-meeting-chat')).toBeVisible()
  await expect(guest.getByTestId('chat-meeting-message')).toHaveCount(0)
  await guest.getByTestId('chat-link-call-leave').click()
  // The owner's leave button asks which: leave, or end it for everyone.
  const recorded = chat.waitForRequest((sent) => sent.method() === 'POST' && new URL(sent.url()).pathname === '/api/chat/joined-meetings')
  await ownerCall.getByTestId('chat-link-call-leave-menu').click()
  await ownerCall.getByTestId('chat-link-call-leave').click()
  await expect(ownerCall.getByTestId('chat-link-call-left')).toBeVisible({ timeout: 30_000 })
  await ownerCall.close()

  // The owner's stay is in the account's list of joined meetings, and can
  // be rejoined. The meeting page left it in this browser; Chat moved it
  // into the account, sealed, so it is there without this browser's copy.
  const entry = chat.locator(`[data-testid="chat-meeting-history-entry"][data-title="${title}"]`)
  await expect(entry).toHaveCount(1, { timeout: 30_000 })
  await expect(entry.getByTestId('chat-meeting-rejoin')).toHaveAttribute('href', url)
  await expect.poll(() => chat.evaluate(() => localStorage.getItem('kutup-meeting-history')), { timeout: 30_000 }).toBe('[]')
  const recordedBody = (await recorded).postData() ?? ''
  expect(Object.keys(JSON.parse(recordedBody) as Record<string, unknown>).sort()).toEqual(['entry', 'id'])
  expect(recordedBody).not.toContain('Team sync')
  await chat.reload()
  await chat.getByRole('link', { name: 'Meetings', exact: true }).click()
  await expect(entry).toHaveCount(1, { timeout: 60_000 })
  // The guest has no account: their stays are kept nowhere, so they cannot
  // end up in the list of whoever signs in to this browser next.
  expect(await guest.evaluate(() => localStorage.getItem('kutup-meeting-history'))).toBeNull()

  // Renaming it changes what a holder of the link sees.
  await meeting(chat, title).getByTestId('chat-meeting-edit').click()
  const renamed = `${title} (moved)`
  await chat.getByTestId('chat-meeting-title').fill(renamed)
  await chat.getByTestId('chat-meeting-save').click()
  await expect(meeting(chat, renamed)).toBeVisible({ timeout: 30_000 })
  await guest.reload()
  await expect(guest.getByTestId('chat-link-call-title')).toHaveText(renamed, { timeout: 60_000 })

  // Deleting it: nobody can join through the link any more.
  await meeting(chat, renamed).getByTestId('chat-meeting-delete').click()
  await chat.getByRole('alertdialog').getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(meeting(chat, renamed)).toHaveCount(0, { timeout: 30_000 })
  await guest.reload()
  await expect(guest.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'gone', { timeout: 60_000 })
  await expect(guest.getByTestId('chat-link-call-name')).toHaveCount(0)

  await guestContext.close()
  await ownerContext.close()
})

test('a meeting starts from the sidebar and from a conversation', async ({ browser }) => {
  test.slow()
  const tag = Date.now()
  const alice = newAccount('meetalice', PASSWORD)
  const bob = newAccount('meetbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  test.skip(!(await hostsMeetings(pageA)), 'this stack has no SFU (docker compose --profile sfu)')
  const pageB = await openChat(contextB)
  const settings = (await (await pageA.request.get(apiUrl('/auth/settings'))).json()) as { chat: { serverName: string } }

  // "New meeting" in the sidebar makes one to join right away.
  await pageA.getByTestId('chat-new-meeting').click()
  await expect(pageA.getByTestId('chat-meetings-yours').getByTestId('chat-meeting')).toHaveCount(1, { timeout: 30_000 })
  await expect(pageA.getByTestId('chat-meeting-when')).toHaveText('No set time')

  // From a conversation: the link goes to the other person as a message.
  await openChats(pageA)
  await openDirectChat(pageA, `${bob.username}@${settings.chat.serverName}`)
  await send(pageA, `hello-${tag}`)
  await openConversationWith(pageB, alice.username)
  await expect(message(pageB, `hello-${tag}`)).toBeVisible({ timeout: 45_000 })
  await acceptRequest(pageB)
  await pageA.getByTestId('chat-thread-menu').click()
  await pageA.getByTestId('chat-start-meeting').click()
  const invitation = pageB.getByTestId('chat-message').filter({ hasText: 'Join the meeting:' })
  await expect(invitation).toBeVisible({ timeout: 45_000 })
  const url = /https?:\/\/\S+\/call#[A-Za-z0-9_-]{44}/.exec((await invitation.textContent()) ?? '')?.[0]
  expect(url).toBeTruthy()

  // Bob opens it and can join; Alice now has two meetings.
  const bobCall = await contextB.newPage()
  await bobCall.goto(url!)
  await expect(bobCall.getByTestId('chat-link-call-title')).toHaveText('Meeting', { timeout: 60_000 })
  await join(bobCall, 'Bob', false)
  await bobCall.getByTestId('chat-link-call-leave').click()
  await pageA.getByRole('link', { name: 'Meetings', exact: true }).click()
  await expect(pageA.getByTestId('chat-meetings-yours').getByTestId('chat-meeting')).toHaveCount(2, { timeout: 30_000 })

  await contextA.close()
  await contextB.close()
})

test('after its owner signs out, their meeting in that browser waits like anyone', async ({ browser }) => {
  test.slow()
  const owner = newAccount('doorleaver', PASSWORD)
  const context = await browser.newContext()
  await registerAccount(context, owner)
  const chat = await openChat(context)
  test.skip(!(await hostsMeetings(chat)), 'this stack has no SFU (docker compose --profile sfu)')

  await chat.getByRole('link', { name: 'Meetings', exact: true }).click()
  await chat.getByTestId('chat-meeting-schedule').click()
  const title = `Left ${Date.now()}`
  await chat.getByTestId('chat-meeting-title').fill(title)
  await chat.getByTestId('chat-meeting-timed').uncheck()
  await chat.getByTestId('chat-meeting-waiting-room').check()
  await chat.getByTestId('chat-meeting-save').click()
  await expect(meeting(chat, title).getByTestId('chat-meeting-has-waiting-room')).toBeVisible({ timeout: 30_000 })
  const url = (await meeting(chat, title).getByTestId('chat-meeting-url').textContent())!.trim()

  // Signed in, this browser hosts it: no waiting.
  const signedIn = await context.newPage()
  await signedIn.goto(url)
  await expect(signedIn.getByTestId('chat-link-call-name')).toBeVisible({ timeout: 60_000 })
  await expect(signedIn.getByTestId('chat-link-call-has-waiting-room')).toHaveCount(0)
  await signedIn.close()

  // Signed out: the same browser is a guest, who has to ask.
  await chat.getByRole('button', { name: 'Account menu' }).click()
  await chat.getByRole('menuitem', { name: 'Sign out' }).click()
  await chat.waitForURL((address) => address.pathname.startsWith('/login'), { timeout: 60_000 })
  const signedOut = await context.newPage()
  await signedOut.goto(url)
  await expect(signedOut.getByTestId('chat-link-call-name')).toBeVisible({ timeout: 60_000 })
  await expect(signedOut.getByTestId('chat-link-call-has-waiting-room')).toBeVisible()
  expect(await signedOut.evaluate(() => localStorage.getItem('kutup-meeting-hosts'))).toBeNull()
  await context.close()
})

test('a meeting with a waiting room lets in only whom its owner admits', async ({ browser }) => {
  test.slow()
  const owner = newAccount('doorowner', PASSWORD)
  const ownerContext = await browser.newContext()
  await registerAccount(ownerContext, owner)
  const chat = await openChat(ownerContext)
  test.skip(!(await hostsMeetings(chat)), 'this stack has no SFU (docker compose --profile sfu)')

  // A meeting with a waiting room.
  await chat.getByRole('link', { name: 'Meetings', exact: true }).click()
  await chat.getByTestId('chat-meeting-schedule').click()
  const title = `Board ${Date.now()}`
  await chat.getByTestId('chat-meeting-title').fill(title)
  await chat.getByTestId('chat-meeting-timed').uncheck()
  await chat.getByTestId('chat-meeting-waiting-room').check()
  await chat.getByTestId('chat-meeting-save').click()
  await expect(meeting(chat, title).getByTestId('chat-meeting-has-waiting-room')).toBeVisible({ timeout: 30_000 })
  const url = (await meeting(chat, title).getByTestId('chat-meeting-url').textContent())!.trim()

  // The owner, signed in on this browser, comes straight in.
  const popup = ownerContext.waitForEvent('page')
  await meeting(chat, title).getByTestId('chat-meeting-join').click()
  const ownerCall = await popup
  await expect(ownerCall.getByTestId('chat-link-call-has-waiting-room')).toHaveCount(0)
  await join(ownerCall, 'Owner Ada', false)

  // A guest holds the link, and that is not enough: the page says the host
  // lets people in, and the server refuses an SFU token for the link alone.
  const guestContext = await browser.newContext()
  const guest = await guestContext.newPage()
  let tokenRequest: { roomId: string; accessToken: string } | null = null
  guest.on('request', (sent) => {
    if (new URL(sent.url()).pathname === '/api/chat/call-links/info') tokenRequest = sent.postDataJSON() as typeof tokenRequest
  })
  await guest.goto(url)
  await expect(guest.getByTestId('chat-link-call-has-waiting-room')).toBeVisible({ timeout: 60_000 })
  expect(tokenRequest).not.toBeNull()
  const direct = await guest.request.post(apiUrl('/chat/call-links/token'), {
    data: { ...tokenRequest!, participantId: 'ab'.repeat(16), seat: Buffer.alloc(32, 3).toString('base64'), label: Buffer.alloc(168).toString('base64') },
  })
  expect(direct.status()).toBe(403)
  const asHost = await guest.request.post(apiUrl('/chat/call-links/knocks'), {
    data: { ...tokenRequest!, hostToken: Buffer.alloc(32, 7).toString('base64') },
  })
  expect(asHost.status()).toBe(404)

  // The guest asks to join and waits; the owner sees them by name and lets
  // them in.
  await guest.getByTestId('chat-link-call-name').fill('Guest Gül')
  await guest.getByTestId('chat-link-call-join').click()
  await expect(guest.getByTestId('chat-link-call-waiting')).toBeVisible({ timeout: 30_000 })
  const knock = ownerCall.locator('[data-testid="chat-meeting-knock"][data-name="Guest Gül"]')
  await expect(knock).toBeVisible({ timeout: 30_000 })
  await expect(tile(ownerCall, 'Guest Gül')).toHaveCount(0)
  await knock.getByTestId('chat-meeting-admit').click()
  await expect(guest.getByTestId('chat-link-call-screen')).toHaveAttribute('data-phase', 'active', { timeout: 60_000 })
  await expect(tile(ownerCall, 'Guest Gül')).toBeVisible({ timeout: 60_000 })
  await expect(ownerCall.getByTestId('chat-meeting-knocks')).toHaveCount(0, { timeout: 30_000 })

  // Someone the owner turns away is told so, and is not in the meeting.
  const strangerContext = await browser.newContext()
  const stranger = await strangerContext.newPage()
  await stranger.goto(url)
  await expect(stranger.getByTestId('chat-link-call-name')).toBeVisible({ timeout: 60_000 })
  await stranger.getByTestId('chat-link-call-name').fill('Stranger')
  await stranger.getByTestId('chat-link-call-join').click()
  const strangerKnock = ownerCall.locator('[data-testid="chat-meeting-knock"][data-name="Stranger"]')
  await expect(strangerKnock).toBeVisible({ timeout: 30_000 })
  await strangerKnock.getByTestId('chat-meeting-turn-away').click()
  await expect(stranger.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'turnedAway', { timeout: 30_000 })
  await expect(tile(ownerCall, 'Stranger')).toHaveCount(0)

  // Someone who gives up waiting disappears from the owner's list.
  await stranger.getByTestId('chat-link-call-join').click()
  await expect(stranger.getByTestId('chat-link-call-waiting')).toBeVisible({ timeout: 30_000 })
  await expect(ownerCall.locator('[data-testid="chat-meeting-knock"][data-name="Stranger"]')).toBeVisible({ timeout: 30_000 })
  await stranger.getByTestId('chat-link-call-waiting-cancel').click()
  await expect(stranger.getByTestId('chat-link-call-name')).toBeVisible()
  await expect(stranger.getByTestId('chat-link-call-left')).toHaveCount(0)
  await expect(ownerCall.getByTestId('chat-meeting-knocks')).toHaveCount(0, { timeout: 45_000 })

  // Turning the waiting room off: the link alone lets people in again.
  await meeting(chat, title).getByTestId('chat-meeting-edit').click()
  await chat.getByTestId('chat-meeting-waiting-room').uncheck()
  await chat.getByTestId('chat-meeting-save').click()
  await expect(meeting(chat, title).getByTestId('chat-meeting-has-waiting-room')).toHaveCount(0, { timeout: 30_000 })
  await stranger.reload()
  await expect(stranger.getByTestId('chat-link-call-name')).toBeVisible({ timeout: 60_000 })
  await expect(stranger.getByTestId('chat-link-call-has-waiting-room')).toHaveCount(0)
  await join(stranger, 'Stranger', false)
  await expect(tile(ownerCall, 'Stranger')).toBeVisible({ timeout: 60_000 })

  await strangerContext.close()
  await guestContext.close()
  await ownerContext.close()
})

function person(page: Page, name: string) {
  return page.locator(`[data-testid="chat-call-person"][data-name="${name}"]`)
}

/** An account's meeting with this title, without a waiting room, and its link. */
async function makeMeeting(chat: Page, title: string): Promise<string> {
  await chat.getByRole('link', { name: 'Meetings', exact: true }).click()
  await chat.getByTestId('chat-meeting-schedule').click()
  await chat.getByTestId('chat-meeting-title').fill(title)
  await chat.getByTestId('chat-meeting-timed').uncheck()
  await chat.getByTestId('chat-meeting-save').click()
  await expect(meeting(chat, title)).toBeVisible({ timeout: 30_000 })
  return (await meeting(chat, title).getByTestId('chat-meeting-url').textContent())!.trim()
}

test('hosts remove and mute people and stop a screen share; the owner names co-hosts and ends the meeting', async ({ browser }) => {
  test.slow()
  const owner = newAccount('hostowner', PASSWORD)
  const ownerContext = await browser.newContext()
  await registerAccount(ownerContext, owner)
  const chat = await openChat(ownerContext)
  test.skip(!(await hostsMeetings(chat)), 'this stack has no SFU (docker compose --profile sfu)')

  // A meeting anyone with the link walks into.
  const title = `Town hall ${Date.now()}`
  const url = await makeMeeting(chat, title)
  const popup = ownerContext.waitForEvent('page')
  await meeting(chat, title).getByTestId('chat-meeting-join').click()
  const ownerCall = await popup
  // The owner is signed in here, and shows the others their account.
  await expect(ownerCall.getByTestId('chat-link-call-show-account')).toBeChecked({ timeout: 60_000 })
  await join(ownerCall, 'Owner Ada', false)

  // Two people join with the link. What one of them shows the server to ask
  // who the hosts are is kept, to try as a co-host what a co-host may not do.
  const helperContext = await browser.newContext()
  const helper = await helperContext.newPage()
  let asHelper: { roomId: string; accessToken: string; sfuToken: string } | null = null
  let ownerId: string | null = null
  helper.on('response', async (response) => {
    if (new URL(response.url()).pathname !== '/api/chat/call-links/roles' || !response.ok()) return
    asHelper = response.request().postDataJSON() as typeof asHelper
    const { roles } = (await response.json()) as { roles: { participantId: string; role: string }[] }
    ownerId = roles.find((entry) => entry.role === 'owner')?.participantId ?? ownerId
  })
  await helper.goto(url)
  await expect(helper.getByTestId('chat-link-call-name')).toBeVisible({ timeout: 60_000 })
  // Nobody is signed in there: there is no account to show.
  await expect(helper.getByTestId('chat-link-call-show-account')).toHaveCount(0)
  await join(helper, 'Helper Hale', false)
  const pestContext = await browser.newContext()
  const pest = await pestContext.newPage()
  // The SFU token this one is given is kept, to try it again once removed.
  let pestAccess: { url: string; token: string } | null = null
  pest.on('response', async (response) => {
    if (new URL(response.url()).pathname === '/api/chat/call-links/token' && response.ok()) pestAccess = (await response.json()) as typeof pestAccess
  })
  await pest.goto(url)
  await expect(pest.getByTestId('chat-link-call-name')).toBeVisible({ timeout: 60_000 })
  await join(pest, 'Pest', false)
  await expect(tile(ownerCall, 'Pest')).toBeVisible({ timeout: 60_000 })

  // Everyone sees who the host is, and the account the server vouches for
  // under the name they typed. A guest has none. Someone who is not a host
  // can act on nobody.
  await helper.getByTestId('chat-call-people-button').click()
  await expect(person(helper, 'Owner Ada').getByTestId('chat-call-person-badge')).toHaveText('Host', { timeout: 30_000 })
  await expect(person(helper, 'Owner Ada').getByTestId('chat-call-person-account')).toContainText(`${owner.username}@`)
  await expect(person(helper, 'Pest')).toBeVisible({ timeout: 30_000 })
  await expect(person(helper, 'Pest').getByTestId('chat-call-person-account')).toHaveCount(0)
  await expect(helper.getByTestId('chat-meeting-person-menu')).toHaveCount(0)
  await expect(helper.getByTestId('chat-link-call-leave-menu')).toHaveCount(0)
  await expect(helper.getByTestId('chat-meeting-mute-all')).toHaveCount(0)
  expect(asHelper).not.toBeNull()
  expect(ownerId).not.toBeNull()
  const refused = await helper.request.post(apiUrl('/chat/call-links/participants/remove'), {
    data: { ...asHelper!, participantId: ownerId! },
  })
  expect(refused.status()).toBe(404)
  // Nobody takes someone else's identity: a token for the owner's is minted
  // only to the browser that holds its seat.
  const { roomId, accessToken } = asHelper!
  const stolen = await helper.request.post(apiUrl('/chat/call-links/token'), {
    data: { roomId, accessToken, participantId: ownerId!, seat: Buffer.alloc(32, 9).toString('base64'), label: Buffer.alloc(168).toString('base64') },
  })
  expect(stolen.status()).toBe(409)

  // The owner mutes someone: their microphone goes off, and they can turn
  // it back on themselves.
  await ownerCall.getByTestId('chat-call-people-button').click()
  await expect(pest.getByTestId('chat-link-call-mute')).toHaveAttribute('aria-pressed', 'false')
  await person(ownerCall, 'Pest').getByTestId('chat-meeting-person-menu').click()
  await ownerCall.getByTestId('chat-meeting-mute').click()
  await expect(pest.getByTestId('chat-link-call-mute')).toHaveAttribute('aria-pressed', 'true', { timeout: 30_000 })
  await pest.getByTestId('chat-link-call-mute').click()
  await expect(pest.getByTestId('chat-link-call-mute')).toHaveAttribute('aria-pressed', 'false', { timeout: 30_000 })
  // Muting everyone leaves the hosts' microphones on.
  await ownerCall.getByTestId('chat-meeting-mute-all').click()
  await expect(pest.getByTestId('chat-link-call-mute')).toHaveAttribute('aria-pressed', 'true', { timeout: 30_000 })
  await expect(helper.getByTestId('chat-link-call-mute')).toHaveAttribute('aria-pressed', 'true', { timeout: 30_000 })
  await expect(ownerCall.getByTestId('chat-link-call-mute')).toHaveAttribute('aria-pressed', 'false')

  // The owner stops someone's screen share: it ends, and they cannot start
  // another until a host allows it again.
  await pest.getByTestId('chat-link-call-screen-share').click()
  await expect(ownerCall.getByTestId('chat-group-call-screen-tile')).toBeVisible({ timeout: 60_000 })
  await person(ownerCall, 'Pest').getByTestId('chat-meeting-person-menu').click()
  await expect(ownerCall.getByTestId('chat-meeting-screen')).toHaveText('Stop their screen sharing')
  await ownerCall.getByTestId('chat-meeting-screen').click()
  await expect(ownerCall.getByTestId('chat-group-call-screen-tile')).toHaveCount(0, { timeout: 45_000 })
  await expect(pest.getByTestId('chat-link-call-screen-share')).toBeDisabled({ timeout: 30_000 })
  await person(ownerCall, 'Pest').getByTestId('chat-meeting-person-menu').click()
  await expect(ownerCall.getByTestId('chat-meeting-screen')).toHaveText('Allow screen sharing', { timeout: 30_000 })
  await ownerCall.getByTestId('chat-meeting-screen').click()
  await expect(pest.getByTestId('chat-link-call-screen-share')).toBeEnabled({ timeout: 30_000 })

  // The owner makes one of them a co-host.
  await person(ownerCall, 'Helper Hale').getByTestId('chat-meeting-person-menu').click()
  await ownerCall.getByTestId('chat-meeting-co-host').click()
  await expect(person(ownerCall, 'Helper Hale').getByTestId('chat-call-person-badge')).toHaveText('Co-host', { timeout: 30_000 })
  await expect(person(helper, 'You').getByTestId('chat-call-person-badge')).toHaveText('Co-host', { timeout: 30_000 })

  // A co-host is still one after reloading the page: the browser comes back
  // to its seat.
  await helper.reload()
  await join(helper, 'Helper Hale', false)
  await helper.getByTestId('chat-call-people-button').click()
  await expect(person(helper, 'You').getByTestId('chat-call-person-badge')).toHaveText('Co-host', { timeout: 30_000 })

  // A co-host acts on those who are not hosts, never on the owner, and does
  // not end the meeting.
  await expect(person(helper, 'Pest').getByTestId('chat-meeting-person-menu')).toBeVisible({ timeout: 30_000 })
  await expect(person(helper, 'Owner Ada').getByTestId('chat-meeting-person-menu')).toHaveCount(0)
  await expect(helper.getByTestId('chat-link-call-leave-menu')).toHaveCount(0)
  const notTheOwner = await helper.request.post(apiUrl('/chat/call-links/participants/remove'), {
    data: { ...asHelper!, participantId: ownerId! },
  })
  expect(notTheOwner.status()).toBe(403)
  const notTheirs = await helper.request.post(apiUrl('/chat/call-links/end'), { data: asHelper! })
  expect(notTheirs.status()).toBe(404)

  // The co-host removes someone: they are told, and the meeting now has a
  // waiting room, so the link alone no longer lets them back in.
  await person(helper, 'Pest').getByTestId('chat-meeting-person-menu').click()
  await helper.getByTestId('chat-meeting-remove').click()
  await helper.getByRole('alertdialog').getByRole('button', { name: 'Remove from meeting' }).click()
  await expect(pest.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'removed', { timeout: 45_000 })
  await expect(tile(ownerCall, 'Pest')).toHaveCount(0, { timeout: 45_000 })
  await expect(pest.getByTestId('chat-link-call-has-waiting-room')).toBeVisible({ timeout: 30_000 })

  // The SFU token they were given still works at the SFU, which cannot take
  // it back. Connecting with it again gets them removed again by the server,
  // without a host doing anything.
  expect(pestAccess).not.toBeNull()
  const back = await pest.evaluate(
    ({ url: sfu, token }) =>
      new Promise<string>((resolve) => {
        const socket = new WebSocket(`${sfu}/rtc?access_token=${encodeURIComponent(token)}&auto_subscribe=1&protocol=9`)
        let opened = false
        socket.onopen = () => (opened = true)
        socket.onclose = () => resolve(opened ? 'removed again' : 'refused')
        setTimeout(() => resolve('still connected'), 40_000)
      }),
    pestAccess!,
  )
  expect(back).toBe('removed again')
  await expect(tile(ownerCall, 'Pest')).toHaveCount(0)

  // They ask again; the co-host sees them waiting and lets them in.
  await pest.getByTestId('chat-link-call-join').click()
  await expect(pest.getByTestId('chat-link-call-waiting')).toBeVisible({ timeout: 30_000 })
  const knock = helper.locator('[data-testid="chat-meeting-knock"][data-name="Pest"]')
  await expect(knock).toBeVisible({ timeout: 30_000 })
  await knock.getByTestId('chat-meeting-admit').click()
  await expect(pest.getByTestId('chat-link-call-screen')).toHaveAttribute('data-phase', 'active', { timeout: 60_000 })
  await expect(tile(ownerCall, 'Pest')).toBeVisible({ timeout: 60_000 })

  // The owner takes the co-host's role back: they can act on nobody again.
  await person(ownerCall, 'Helper Hale').getByTestId('chat-meeting-person-menu').click()
  await ownerCall.getByTestId('chat-meeting-co-host').click()
  await expect(person(ownerCall, 'Helper Hale').getByTestId('chat-call-person-badge')).toHaveCount(0, { timeout: 30_000 })
  await expect(helper.getByTestId('chat-meeting-person-menu')).toHaveCount(0, { timeout: 30_000 })

  // The owner ends the meeting: everyone is out and told why, and the SFU
  // tokens of the sitting that ended say nothing about the next one.
  await ownerCall.getByTestId('chat-link-call-leave-menu').click()
  await ownerCall.getByTestId('chat-meeting-end').click()
  await ownerCall.getByRole('alertdialog').getByRole('button', { name: 'End meeting' }).click()
  await expect(helper.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'endedByHost', { timeout: 45_000 })
  await expect(pest.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'endedByHost', { timeout: 45_000 })
  await expect(ownerCall.getByTestId('chat-link-call-left')).toBeVisible({ timeout: 30_000 })
  await expect(ownerCall.getByTestId('chat-link-call-failure')).toHaveCount(0)
  const afterwards = await helper.request.post(apiUrl('/chat/call-links/roles'), { data: asHelper! })
  expect(afterwards.ok()).toBe(true)
  expect(await afterwards.json()).toMatchObject({ roles: [] })

  await pestContext.close()
  await helperContext.close()
  await ownerContext.close()
})

test('a meeting is locked, gets a co-host when its hosts leave, and can be given a new link', async ({ browser }) => {
  test.slow()
  const owner = newAccount('lockowner', PASSWORD)
  const ownerContext = await browser.newContext()
  await registerAccount(ownerContext, owner)
  const chat = await openChat(ownerContext)
  test.skip(!(await hostsMeetings(chat)), 'this stack has no SFU (docker compose --profile sfu)')

  const title = `Workshop ${Date.now()}`
  const url = await makeMeeting(chat, title)
  const popup = ownerContext.waitForEvent('page')
  await meeting(chat, title).getByTestId('chat-meeting-join').click()
  const ownerCall = await popup
  await join(ownerCall, 'Owner Ada', false)
  const firstContext = await browser.newContext()
  const first = await firstContext.newPage()
  await first.goto(url)
  await join(first, 'First Fatma', false)
  await expect(tile(ownerCall, 'First Fatma')).toBeVisible({ timeout: 60_000 })

  // Locked: someone new with the link is told so and does not get in;
  // someone already in the meeting sees that it is locked.
  await ownerCall.getByTestId('chat-call-people-button').click()
  await ownerCall.getByTestId('chat-meeting-lock').click()
  await expect(ownerCall.getByTestId('chat-meeting-lock')).toHaveAttribute('data-locked', 'true', { timeout: 30_000 })
  await first.getByTestId('chat-call-people-button').click()
  await expect(first.getByTestId('chat-meeting-locked')).toBeVisible({ timeout: 30_000 })
  const lateContext = await browser.newContext()
  const late = await lateContext.newPage()
  await late.goto(url)
  await expect(late.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'locked', { timeout: 60_000 })
  await late.getByTestId('chat-link-call-name').fill('Late Leyla')
  await late.getByTestId('chat-link-call-join').click()
  await expect(late.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'locked', { timeout: 30_000 })
  await expect(tile(ownerCall, 'Late Leyla')).toHaveCount(0)

  // Unlocked, they come in.
  await ownerCall.getByTestId('chat-meeting-lock').click()
  await expect(ownerCall.getByTestId('chat-meeting-lock')).toHaveAttribute('data-locked', 'false', { timeout: 30_000 })
  await late.reload()
  await join(late, 'Late Leyla', false)
  await expect(tile(ownerCall, 'Late Leyla')).toBeVisible({ timeout: 60_000 })

  // The owner leaves without ending the meeting. It is not left without
  // anyone to let people in: after a short while the participant who has
  // been there longest is a co-host, and is told so.
  await ownerCall.getByTestId('chat-link-call-leave-menu').click()
  await ownerCall.getByTestId('chat-link-call-leave').click()
  await expect(ownerCall.getByTestId('chat-link-call-left')).toBeVisible({ timeout: 30_000 })
  await expect(person(first, 'You').getByTestId('chat-call-person-badge')).toHaveText('Co-host', { timeout: 90_000 })
  await expect(person(first, 'Late Leyla').getByTestId('chat-meeting-person-menu')).toBeVisible({ timeout: 30_000 })
  await late.getByTestId('chat-call-people-button').click()
  await expect(person(late, 'First Fatma').getByTestId('chat-call-person-badge')).toHaveText('Co-host', { timeout: 30_000 })
  await expect(person(late, 'You').getByTestId('chat-call-person-badge')).toHaveCount(0)
  await ownerCall.close()

  // A new link: the old one stops working and whoever was in the meeting is
  // out; the meeting keeps its title under the new link.
  await meeting(chat, title).getByTestId('chat-meeting-new-link').click()
  await chat.getByRole('alertdialog').getByRole('button', { name: 'New link' }).click()
  await expect(meeting(chat, title).getByTestId('chat-meeting-url')).not.toHaveText(url, { timeout: 30_000 })
  const newUrl = (await meeting(chat, title).getByTestId('chat-meeting-url').textContent())!.trim()
  await expect(chat.getByTestId('chat-meetings-yours').getByTestId('chat-meeting')).toHaveCount(1)
  await expect(first.getByTestId('chat-link-call-failure')).toBeVisible({ timeout: 45_000 })
  await first.reload()
  await expect(first.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'gone', { timeout: 60_000 })
  await late.goto(newUrl)
  await late.reload()
  await expect(late.getByTestId('chat-link-call-title')).toHaveText(title, { timeout: 60_000 })
  await join(late, 'Late Leyla', false)

  await lateContext.close()
  await firstContext.close()
  await ownerContext.close()
})

test('a changed or incomplete link is refused before anything is sent', async ({ browser }) => {
  const context = await browser.newContext()
  const page = await context.newPage()
  const api: string[] = []
  page.on('request', (sent) => {
    if (new URL(sent.url()).pathname.startsWith('/api/chat/')) api.push(sent.url())
  })
  await page.goto(appUrl('chat', '/call#not-a-link'))
  await expect(page.getByRole('heading', { name: 'This is not a meeting link' })).toBeVisible({ timeout: 60_000 })
  expect(api).toEqual([])
  await context.close()
})
