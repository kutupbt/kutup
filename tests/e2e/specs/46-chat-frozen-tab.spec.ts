// Fault injection: a browser tab that froze while holding Chat's engine lock
// (docs/chat-protocol.md, "Browser storage"). One of Alice's tabs takes the
// lock and never lets go or says it is alive, as a frozen tab does; her other
// tab must take it over and keep working, instead of waiting for ever.

import { expect, test } from '@playwright/test'
import { apiUrl, newAccount, registerAccount } from '../fixtures/apps'
import { acceptRequest, message, openChat, openConversationWith, openDirectChat, send } from '../fixtures/chat'

const PASSWORD = 'Deneme123*FrozenTabPassword'

declare global {
  interface Window { __chatEngineLocks?: Set<string> }
}

test('a tab frozen while holding the chat lock does not stall the other tabs', async ({ browser, request }) => {
  test.slow()
  const settings = (await (await request.get(apiUrl('/auth/settings'))).json()) as {
    chat: { serverName: string }
  }
  const tag = Date.now()
  const alice = newAccount('frozenalice', PASSWORD)
  const bob = newAccount('frozenbob', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  // Record the engine lock's name as Chat asks for it.
  await contextA.addInitScript(() => {
    const locks = navigator.locks
    const request = locks.request.bind(locks) as (...args: unknown[]) => Promise<unknown>
    window.__chatEngineLocks = new Set()
    locks.request = ((name: string, ...rest: unknown[]) => {
      if (/^kutup-chat-engine:/.test(name) && !/:(mls-workflow|attachment-ledger)$/.test(name)) {
        window.__chatEngineLocks!.add(name)
      }
      return request(name, ...rest)
    }) as typeof locks.request
  })
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)
  const frozen = await openChat(contextA)
  const pageB = await openChat(contextB)

  const first = `before-${tag}`
  await openDirectChat(frozen, `${bob.username}@${settings.chat.serverName}`)
  await send(frozen, first)
  await openConversationWith(pageB, alice.username)
  await expect(message(pageB, first)).toBeVisible({ timeout: 45_000 })
  await acceptRequest(pageB)

  // The "frozen" tab takes the engine lock and never answers again.
  const lockName = await frozen.evaluate(() => [...(window.__chatEngineLocks ?? [])][0])
  expect(lockName).toBeTruthy()
  await frozen.evaluate((name) => {
    void navigator.locks.request(name, { mode: 'exclusive' }, () => new Promise(() => {})).catch(() => {})
  }, lockName)
  await expect.poll(async () => (await frozen.evaluate(async (name) =>
    (await navigator.locks.query()).held?.some((lock) => lock.name === name) ?? false, lockName)), { timeout: 30_000 }).toBe(true)

  // Alice's other tab opens Chat and writes: it waits out the silence (30 s),
  // takes the lock over, and the message goes through.
  const working = await openChat(contextA)
  const second = `after-${tag}`
  await openDirectChat(working, `${bob.username}@${settings.chat.serverName}`)
  await send(working, second)
  await expect(message(pageB, second)).toBeVisible({ timeout: 120_000 })

  await contextA.close()
  await contextB.close()
})
