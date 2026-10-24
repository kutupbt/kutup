// Calls in the browser, with a synthetic camera, microphone and screen
// (playwright.config.ts): a one-to-one call with the People panel, the
// conversation's chat beside the video, and screen sharing. Group calls come
// to pairwise groups in slice 4 (docs/plans/pairwise-groups.md).

import { expect, test, type Page } from '@playwright/test'
import { apiUrl, newAccount, registerAccount } from '../fixtures/apps'
import {
  acceptRequest,
  composer,
  message,
  openChat,
  openConversationWith,
  openDirectChat,
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
