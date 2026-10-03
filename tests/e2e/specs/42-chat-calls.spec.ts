// Calls in the browser, with a synthetic camera, microphone and screen
// (playwright.config.ts): a one-to-one call and a group call, each with the
// People panel, the conversation's chat beside the video, and screen sharing.
// The group call needs an SFU (`docker compose --profile sfu`), so that test
// skips on a stack without one.

import { expect, test, type Page } from '@playwright/test'
import { apiUrl, newAccount, registerAccount } from '../fixtures/apps'
import {
  acceptGroup,
  acceptRequest,
  composer,
  createGroup,
  message,
  openChat,
  openConversationWith,
  openDirectChat,
  openGroup,
  send,
} from '../fixtures/chat'

const PASSWORD = 'Deneme123*CallsPassword'

async function settings(page: Page) {
  return (await (await page.request.get(apiUrl('/auth/settings'))).json()) as {
    chat: { serverName: string; groupCalls?: boolean }
  }
}

/** The message box inside the call's chat panel. */
function panelComposer(page: Page) {
  return page.getByTestId('chat-call-panel').getByPlaceholder('Message', { exact: true })
}

async function videoPlays(page: Page, testId: string): Promise<void> {
  await expect
    .poll(() => page.getByTestId(testId).evaluate((video) => (video as HTMLVideoElement).videoWidth), { timeout: 45_000 })
    .toBeGreaterThan(0)
}

test('a one-to-one video call has people, chat and screen sharing', async ({ browser }) => {
  test.slow()
  const tag = Date.now()
  const alice = newAccount('callalice', PASSWORD)
  const bob = newAccount('callbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)
  const { chat } = await settings(pageA)

  // Calls ring only between accepted contacts.
  await openDirectChat(pageA, `${bob.username}@${chat.serverName}`)
  await send(pageA, `hello-${tag}`)
  await openConversationWith(pageB, alice.username)
  await expect(message(pageB, `hello-${tag}`)).toBeVisible({ timeout: 45_000 })
  await acceptRequest(pageB)
  await send(pageB, `hi-${tag}`)
  await expect(message(pageA, `hi-${tag}`)).toBeVisible({ timeout: 45_000 })

  await pageA.getByRole('button', { name: 'Video call', exact: true }).click()
  const screenA = pageA.getByTestId('chat-call-screen')
  const screenB = pageB.getByTestId('chat-call-screen')
  await expect(screenB).toHaveAttribute('data-phase', 'incoming', { timeout: 45_000 })
  await expect(screenB.getByTestId('chat-call-brand')).toContainText('Kutup')
  await pageB.getByTestId('chat-call-accept-video').click()
  await expect(screenA).toHaveAttribute('data-phase', 'active', { timeout: 45_000 })
  await expect(screenB).toHaveAttribute('data-phase', 'active', { timeout: 45_000 })
  await videoPlays(pageA, 'chat-call-remote-video')
  await videoPlays(pageB, 'chat-call-remote-video')

  // People: both sides, and this side's own microphone state.
  await pageA.getByTestId('chat-call-people-button').click()
  await expect(pageA.getByTestId('chat-call-person')).toHaveCount(2)
  await pageA.getByTestId('chat-call-mute').click()
  await expect(pageA.getByTestId('chat-call-person').first().getByLabel('Microphone off')).toBeVisible()
  await pageA.getByTestId('chat-call-mute').click()

  // Chat, without leaving the call.
  await pageA.getByTestId('chat-call-tab-chat').click()
  await expect(pageA.getByTestId('chat-call-panel').getByText(`hi-${tag}`)).toBeVisible({ timeout: 30_000 })
  await panelComposer(pageA).fill(`in-call-${tag}`)
  await panelComposer(pageA).press('Enter')
  await pageB.getByTestId('chat-call-chat-button').click()
  await expect(pageB.getByTestId('chat-call-panel').getByText(`in-call-${tag}`)).toBeVisible({ timeout: 45_000 })
  await pageB.getByTestId('chat-call-panel-close').click()
  await expect(pageB.getByTestId('chat-call-panel')).toHaveCount(0)

  // Alice's screen replaces her camera, and the camera comes back after.
  const localA = pageA.getByTestId('chat-call-local-video')
  await expect(localA).toHaveAttribute('data-source', 'camera')
  await pageA.getByTestId('chat-call-screen-share').click()
  await expect(localA).toHaveAttribute('data-source', 'screen', { timeout: 30_000 })
  await expect(pageA.getByTestId('chat-call-sharing')).toBeVisible()
  await videoPlays(pageB, 'chat-call-remote-video')
  await pageA.getByTestId('chat-call-screen-share').click()
  await expect(localA).toHaveAttribute('data-source', 'camera', { timeout: 30_000 })
  await expect(pageA.getByTestId('chat-call-sharing')).toHaveCount(0)

  await pageA.getByTestId('chat-call-hangup').click()
  await expect(screenA).toHaveCount(0, { timeout: 30_000 })
  await expect(screenB).toHaveCount(0, { timeout: 30_000 })
  // The page's own conversation is usable again.
  await expect(composer(pageA)).toBeVisible()

  await contextA.close()
  await contextB.close()
})

test('a group call shows a shared screen to the others', async ({ browser }) => {
  test.slow()
  const tag = Date.now()
  const alice = newAccount('gcallalice', PASSWORD)
  const bob = newAccount('gcallbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const pageA = await openChat(contextA)
  const pageB = await openChat(contextB)
  const { chat } = await settings(pageA)
  test.skip(!chat.groupCalls, 'this stack has no SFU (docker compose --profile sfu)')

  const groupId = await createGroup(pageA, `${bob.username}@${chat.serverName}`, `Call group ${tag}`)
  await acceptGroup(pageB, groupId)
  await openGroup(pageA, groupId)

  await pageA.getByRole('button', { name: 'Start a group video call', exact: true }).click()
  const screenA = pageA.getByTestId('chat-group-call-screen')
  await expect(screenA).toHaveAttribute('data-phase', 'active', { timeout: 60_000 })
  // Bob is rung (a small group) or sees Join in the conversation.
  const ring = pageB.getByTestId('chat-group-call-answer-video')
  const join = pageB.getByTestId('chat-group-call-join')
  await expect(ring.or(join).first()).toBeVisible({ timeout: 60_000 })
  // The ringing screen covers the conversation's own Join button.
  await ((await ring.isVisible()) ? ring : join).click()
  const screenB = pageB.getByTestId('chat-group-call-screen')
  await expect(screenB).toHaveAttribute('data-phase', 'active', { timeout: 60_000 })
  await expect(screenA.getByTestId('chat-group-call-tile')).toHaveCount(2, { timeout: 45_000 })
  await expect(screenB.getByTestId('chat-group-call-tile')).toHaveCount(2, { timeout: 45_000 })
  await expect(screenA.getByTestId('chat-call-brand')).toContainText('Kutup')

  // Alice shares her screen: it takes the stage on both sides.
  await pageA.getByTestId('chat-group-call-screen-share').click()
  await expect(screenA.getByTestId('chat-group-call-screen-tile')).toBeVisible({ timeout: 45_000 })
  await expect(screenB.getByTestId('chat-group-call-screen-tile')).toBeVisible({ timeout: 45_000 })
  await expect
    .poll(() => screenB.getByTestId('chat-group-call-screen-tile').locator('video').evaluate((video) => (video as HTMLVideoElement).videoWidth), { timeout: 45_000 })
    .toBeGreaterThan(0)
  await pageB.getByTestId('chat-call-people-button').click()
  await expect(pageB.getByTestId('chat-call-person')).toHaveCount(2)
  await expect(pageB.getByTestId('chat-call-people').getByLabel('Sharing a screen')).toHaveCount(1)

  // The group's chat, inside the call.
  await pageB.getByTestId('chat-call-tab-chat').click()
  await panelComposer(pageB).fill(`group-in-call-${tag}`)
  await panelComposer(pageB).press('Enter')
  await pageA.getByTestId('chat-call-chat-button').click()
  await expect(pageA.getByTestId('chat-call-panel').getByText(`group-in-call-${tag}`)).toBeVisible({ timeout: 45_000 })

  await pageA.getByTestId('chat-group-call-screen-share').click()
  await expect(screenB.getByTestId('chat-group-call-screen-tile')).toHaveCount(0, { timeout: 45_000 })

  await pageB.getByTestId('chat-group-call-leave').click()
  await pageA.getByTestId('chat-group-call-leave').click()
  await expect(screenA).toHaveCount(0, { timeout: 30_000 })
  await expect(screenB).toHaveCount(0, { timeout: 30_000 })

  await contextA.close()
  await contextB.close()
})
