import { expect, test } from '@playwright/test'
import { newAccount, registerAccount, signIn } from '../fixtures/apps'
import {
  acceptRequest,
  closeDetails,
  composer,
  message,
  openChat,
  openChats,
  openConversationWith,
  openDetails,
  openDirectChat,
  openNoteToSelf,
  openSettings,
  send,
} from '../fixtures/chat'

const PASSWORD = 'Deneme123*MyTestPasswordIsLong'

test.describe('Signal-backed chat', () => {
  test('two accounts exchange encrypted messages and retain local history', async ({ browser }) => {
    test.slow()
    const tag = Date.now()
    const alice = newAccount('chatalice', PASSWORD)
    const bob = newAccount('chatbob', PASSWORD)
    const contextA = await browser.newContext()
    const contextB = await browser.newContext()
    await registerAccount(contextA, alice)
    await registerAccount(contextB, bob)

    // Opening registers each install, publishes its signed device manifest,
    // performs mailbox reconciliation, and starts the WebSocket hint channel.
    const pageA = await openChat(contextA)
    const pageB = await openChat(contextB)

    // Device labels are account-private metadata. Renaming the current
    // installation keeps its immutable numeric protocol id.
    await openSettings(pageA, 'Devices')
    const deviceA = await pageA.getByTestId('chat-device-status').getAttribute('data-device-id')
    expect(deviceA).toMatch(/^\d+$/)
    await pageA.getByTestId(`chat-device-rename-${deviceA}`).click()
    await pageA.getByTestId(`chat-device-name-input-${deviceA}`).fill('Alice laptop')
    await pageA.getByTestId(`chat-device-name-save-${deviceA}`).click()
    await expect(pageA.getByTestId(`chat-device-${deviceA}`)).toContainText('Alice laptop')
    await pageA.reload()
    await expect(pageA.getByTestId(`chat-device-${deviceA}`)).toContainText('Alice laptop', { timeout: 60_000 })
    await expect(pageA.getByTestId('chat-device-status')).toHaveAttribute('data-device-id', deviceA!)
    await openChats(pageA)

    // A second install of Alice extends the signed device manifest. Note to
    // Self is stored locally on the sender and arrives on this linked install
    // as outgoing history via an encrypted sent transcript.
    const contextA2 = await browser.newContext()
    await signIn(contextA2, alice)
    const pageA2 = await openChat(contextA2)
    await openSettings(pageA2, 'Devices')
    await expect(pageA2.getByTestId('chat-device-status')).not.toHaveAttribute('data-device-id', deviceA!)
    await expect(pageA2.getByTestId(`chat-device-${deviceA}`)).toContainText('Alice laptop')
    await openChats(pageA2)

    // Reload the running source after the linked install has committed its
    // signed manifest entry, so it pins that exact generation before it
    // creates sent transcripts for the account's other devices.
    await pageA.reload()
    await openNoteToSelf(pageA)
    // A direct message has to fit again when it is re-sent or copied to the
    // account's other devices: the composer stops long text and says why.
    await composer(pageA).fill('x'.repeat(30_001))
    await expect(pageA.getByText('This is too long for one message. Shorten it, or send it as a file.')).toBeVisible()
    await expect(pageA.getByRole('button', { name: 'Send', exact: true })).toBeDisabled()
    await composer(pageA).fill('')
    const selfNote = `note-to-self-${tag}`
    await send(pageA, selfNote)
    await expect(message(pageA, selfNote)).toBeVisible({ timeout: 30_000 })
    await openNoteToSelf(pageA2)
    await expect(message(pageA2, selfNote)).toBeVisible({ timeout: 60_000 })
    // IndexedDB is the durable source of truth: a reload must not depend on
    // redelivery from the already-acknowledged server mailbox.
    await pageA2.reload()
    await expect(message(pageA2, selfNote)).toBeVisible({ timeout: 60_000 })

    // A rejected request removes the messages; a later one can be accepted.
    const fromA = `from-a-${tag}`
    await openDirectChat(pageA, bob.username)
    await send(pageA, fromA)
    // Until Bob accepts (or on a server without sealed delivery) files cannot
    // go to him: the attach button stays and says why.
    await pageA.getByTestId('chat-attachment-unavailable').click()
    await expect(pageA.getByTestId('chat-media-unavailable')).toBeVisible()
    await expect(pageA.getByTestId('chat-attachment-button')).toHaveCount(0)
    await openConversationWith(pageB, alice.username)
    await expect(message(pageB, fromA)).toBeVisible({ timeout: 30_000 })
    await pageB.getByRole('button', { name: 'Reject', exact: true }).click()
    await expect(message(pageB, fromA)).toHaveCount(0)

    const afterReject = `after-reject-${tag}`
    await send(pageA, afterReject)
    await openConversationWith(pageB, alice.username)
    await expect(message(pageB, afterReject)).toBeVisible({ timeout: 30_000 })
    await acceptRequest(pageB)
    // Alice's linked install has the conversation as sent history.
    await openConversationWith(pageA2, bob.username)
    await expect(message(pageA2, fromA)).toBeVisible({ timeout: 60_000 })
    await pageA2.reload()
    await expect(message(pageA2, fromA)).toBeVisible({ timeout: 60_000 })

    // Blocked messages are acknowledged and discarded on the device. A send
    // can arrive as more than one envelope (a typing indicator, then the
    // message), so before unblocking, wait until everything that arrived has
    // been acknowledged and nothing more is coming: a message still being
    // handled when the block ends is, correctly, shown.
    const arrivals: number[] = []
    const acks: number[] = []
    pageB.on('websocket', (socket) =>
      socket.on('framereceived', (frame) => {
        if (typeof frame.payload === 'string' && frame.payload.includes('"envelope"')) arrivals.push(Date.now())
      }),
    )
    pageB.on('response', (response) => {
      if (response.request().method() === 'POST' && response.url().includes('/api/chat/messages/ack') && response.ok()) acks.push(Date.now())
    })
    await pageB.reload()
    await expect(composer(pageB)).toBeVisible({ timeout: 60_000 })
    await openDetails(pageB)
    await pageB.getByRole('button', { name: /^Block / }).click()
    await expect(pageB.getByRole('button', { name: 'Unblock', exact: true }).first()).toBeVisible({ timeout: 30_000 })
    await closeDetails(pageB)
    const whileBlocked = `while-blocked-${tag}`
    const sentAt = Date.now()
    await send(pageA, whileBlocked)
    await expect
      .poll(() => {
        const last = arrivals.filter((t) => t >= sentAt).at(-1)
        return last !== undefined && acks.some((t) => t >= last) && Date.now() - last > 1_500
      }, { timeout: 45_000 })
      .toBe(true)
    await expect(message(pageB, whileBlocked)).toHaveCount(0)
    await pageB.getByRole('button', { name: 'Unblock', exact: true }).first().click()
    await expect(pageB.getByRole('button', { name: 'Unblock', exact: true })).toHaveCount(0, { timeout: 30_000 })
    const afterUnblock = `after-unblock-${tag}`
    await send(pageA, afterUnblock)
    await expect(message(pageB, afterUnblock)).toBeVisible({ timeout: 45_000 })
    await expect(message(pageB, whileBlocked)).toHaveCount(0)

    const fromB = `from-b-${tag}`
    await send(pageB, fromB)
    await expect(message(pageA, fromB)).toBeVisible({ timeout: 45_000 })

    await pageA.reload()
    await expect(message(pageA, afterReject)).toBeVisible({ timeout: 60_000 })
    await expect(message(pageA, fromB)).toBeVisible({ timeout: 60_000 })

    await contextA.close()
    await contextA2.close()
    await contextB.close()
  })
})
