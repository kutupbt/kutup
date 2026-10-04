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
  await ownerCall.getByTestId('chat-link-call-leave-menu').click()
  await ownerCall.getByTestId('chat-link-call-leave').click()
  await expect(ownerCall.getByTestId('chat-link-call-left')).toBeVisible({ timeout: 30_000 })
  await ownerCall.close()

  // The owner's stay is in this browser's history, and can be rejoined.
  const entry = chat.locator(`[data-testid="chat-meeting-history-entry"][data-title="${title}"]`)
  await expect(entry).toHaveCount(1, { timeout: 30_000 })
  await expect(entry.getByTestId('chat-meeting-rejoin')).toHaveAttribute('href', url)

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
    data: { ...tokenRequest!, participantId: 'ab'.repeat(16), label: Buffer.alloc(168).toString('base64') },
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

test('hosts remove people, the owner names co-hosts and ends the meeting for everyone', async ({ browser }) => {
  test.slow()
  const owner = newAccount('hostowner', PASSWORD)
  const ownerContext = await browser.newContext()
  await registerAccount(ownerContext, owner)
  const chat = await openChat(ownerContext)
  test.skip(!(await hostsMeetings(chat)), 'this stack has no SFU (docker compose --profile sfu)')

  // A meeting anyone with the link walks into.
  await chat.getByRole('link', { name: 'Meetings', exact: true }).click()
  await chat.getByTestId('chat-meeting-schedule').click()
  const title = `Town hall ${Date.now()}`
  await chat.getByTestId('chat-meeting-title').fill(title)
  await chat.getByTestId('chat-meeting-timed').uncheck()
  await chat.getByTestId('chat-meeting-save').click()
  await expect(meeting(chat, title)).toBeVisible({ timeout: 30_000 })
  const url = (await meeting(chat, title).getByTestId('chat-meeting-url').textContent())!.trim()
  const popup = ownerContext.waitForEvent('page')
  await meeting(chat, title).getByTestId('chat-meeting-join').click()
  const ownerCall = await popup
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
  await join(helper, 'Helper Hale', false)
  const pestContext = await browser.newContext()
  const pest = await pestContext.newPage()
  await pest.goto(url)
  await expect(pest.getByTestId('chat-link-call-name')).toBeVisible({ timeout: 60_000 })
  await join(pest, 'Pest', false)
  await expect(tile(ownerCall, 'Pest')).toBeVisible({ timeout: 60_000 })

  // Everyone sees who the host is; someone who is not a host can act on nobody.
  await helper.getByTestId('chat-call-people-button').click()
  await expect(person(helper, 'Owner Ada').getByTestId('chat-call-person-badge')).toHaveText('Host', { timeout: 30_000 })
  await expect(person(helper, 'Pest')).toBeVisible({ timeout: 30_000 })
  await expect(helper.getByTestId('chat-meeting-person-menu')).toHaveCount(0)
  await expect(helper.getByTestId('chat-link-call-leave-menu')).toHaveCount(0)
  expect(asHelper).not.toBeNull()
  expect(ownerId).not.toBeNull()
  const refused = await helper.request.post(apiUrl('/chat/call-links/participants/remove'), {
    data: { ...asHelper!, participantId: ownerId! },
  })
  expect(refused.status()).toBe(404)

  // The owner makes one of them a co-host.
  await ownerCall.getByTestId('chat-call-people-button').click()
  await person(ownerCall, 'Helper Hale').getByTestId('chat-meeting-person-menu').click()
  await ownerCall.getByTestId('chat-meeting-co-host').click()
  await expect(person(ownerCall, 'Helper Hale').getByTestId('chat-call-person-badge')).toHaveText('Co-host', { timeout: 30_000 })
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

  // The owner ends the meeting: everyone is out and told why.
  await ownerCall.getByTestId('chat-link-call-leave-menu').click()
  await ownerCall.getByTestId('chat-meeting-end').click()
  await ownerCall.getByRole('alertdialog').getByRole('button', { name: 'End meeting' }).click()
  await expect(helper.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'endedByHost', { timeout: 45_000 })
  await expect(pest.getByTestId('chat-link-call-failure')).toHaveAttribute('data-reason', 'endedByHost', { timeout: 45_000 })
  await expect(ownerCall.getByTestId('chat-link-call-left')).toBeVisible({ timeout: 30_000 })
  await expect(ownerCall.getByTestId('chat-link-call-failure')).toHaveCount(0)

  await pestContext.close()
  await helperContext.close()
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
