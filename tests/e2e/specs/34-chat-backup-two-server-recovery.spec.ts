import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiUrl, hasSecondaryServer, newAccount, registerAccount, serverDomain, signIn, type Server } from '../fixtures/apps'
import {
  acceptGroup,
  acceptRequest,
  backupCursor,
  createGroup,
  deleteForEveryone,
  editMessage,
  enableReadReceipts,
  message,
  openChat,
  openChats,
  openConversationWith,
  openDirectChat,
  openSettings,
  reactTo,
  reaction,
  replyTo,
  send,
  sendAttachment,
  setDisappearing,
  waitForProtection,
} from '../fixtures/chat'
import { recordSafeCheckpoint } from '../safe-diagnostics'

const PASSWORD = 'Deneme123*FederatedBackupPassword'
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const COMPOSE = resolve(ROOT, 'docker-compose.chat-federation.yml')
const PROJECT = process.env.KUTUP_FEDERATION_PROJECT ?? 'kutup-chat-federation-test'

/** Sends and waits until the sender's own bubble shows. */
async function say(page: Page, text: string): Promise<void> {
  await send(page, text)
  await expect(message(page, text)).toBeVisible({ timeout: 45_000 })
}

/** Messages arrive over the live connection; no manual sync exists. */
async function arrives(page: Page, text: string): Promise<void> {
  await expect(message(page, text)).toBeVisible({ timeout: 45_000 })
}

function attachmentIn(page: Page, filename: string) {
  return page.getByTestId('chat-message').filter({ hasText: filename }).getByText(filename, { exact: true })
}

function compose(args: string[]): string {
  return execFileSync('docker', [
    'compose', '--project-name', PROJECT, '--file', COMPOSE, ...args,
  ], { cwd: ROOT, encoding: 'utf8' }).trim()
}

async function restartHomeservers(
  accounts: Array<{
    server: Server
    postgres: 'postgres-a' | 'postgres-b'
    username: string
  }>,
): Promise<void> {
  const expectedBindings = accounts.map(account => ({
    ...account,
    binding: keyBinding(account.postgres, account.username),
  }))
  // Docker reconnects simultaneously restarted containers to the network in
  // nondeterministic order. Starting nginx in that window can pin backend-a
  // to backend-b's former address (and vice versa) until the next reload.
  // Settle the backend addresses before either edge resolves its upstream.
  compose(['restart', 'backend-a', 'backend-b'])
  compose(['up', '--detach', '--wait', 'backend-a', 'backend-b'])
  compose(['restart', 'edge-a', 'edge-b'])
  for (const url of [apiUrl('/health', 'primary'), apiUrl('/health', 'secondary')]) {
    await expect.poll(async () => {
      try { return (await fetch(url)).ok } catch { return false }
    }, { timeout: 60_000, intervals: [500, 1_000, 2_000] }).toBe(true)
  }
  // The recovery preflight answers an unknown name with a fake binding, so
  // only the persisted account's real one shows the backend serves it.
  for (const account of expectedBindings) {
    await expect.poll(async () => {
      try {
        const response = await fetch(
          apiUrl(`/auth/recover/preflight?name=${encodeURIComponent(account.username)}`, account.server),
        )
        if (!response.ok) return false
        const preflight = await response.json() as { envelopeBinding?: string }
        return preflight.envelopeBinding === account.binding
      } catch {
        return false
      }
    }, {
      timeout: 60_000,
      intervals: [500, 1_000, 2_000],
      message: `restarted ${account.postgres} did not expose its persisted account`,
    }).toBe(true)
  }
}

function backupRows(postgres: 'postgres-a' | 'postgres-b', username: string): number {
  const quoted = username.replaceAll("'", "''")
  const sql = `SELECT COUNT(*) FROM chat_backups b JOIN users u ON u.id=b.user_id WHERE u.username='${quoted}'`
  return Number(compose(['exec', '-T', postgres, 'psql', '-U', 'kutup', '-d', 'kutup', '-Atc', sql]))
}

/** How many entries the account's Chat contact list holds on its server. */
function contactListEntries(postgres: 'postgres-a' | 'postgres-b', username: string): number {
  const quoted = username.replaceAll("'", "''")
  const sql = `SELECT COUNT(*) FROM chat_contact_list c JOIN users u ON u.id=c.user_id WHERE u.username='${quoted}'`
  return Number(compose(['exec', '-T', postgres, 'psql', '-U', 'kutup', '-d', 'kutup', '-Atc', sql]))
}

function keyBinding(
  postgres: 'postgres-a' | 'postgres-b',
  username: string,
): string {
  const quoted = username.replaceAll("'", "''")
  return compose([
    'exec', '-T', postgres, 'psql', '-U', 'kutup', '-d', 'kutup', '-Atc',
    `SELECT key_binding FROM users WHERE username='${quoted}'`,
  ])
}

function backupFacts(
  postgres: 'postgres-a' | 'postgres-b',
  username: string,
): { backups: number; objects: number; media: number } {
  const quoted = username.replaceAll("'", "''")
  const sql = `SELECT COUNT(*),
    (SELECT COUNT(*) FROM chat_backup_segments s WHERE s.user_id=u.id) +
    (SELECT COUNT(*) FROM chat_backup_bases b WHERE b.user_id=u.id) +
    (SELECT COUNT(*) FROM chat_backup_media_objects m WHERE m.user_id=u.id),
    (SELECT COUNT(*) FROM chat_backup_media_objects m WHERE m.user_id=u.id)
    FROM users u JOIN chat_backups cb ON cb.user_id=u.id
    WHERE u.username='${quoted}' GROUP BY u.id`
  const output = compose(['exec', '-T', postgres, 'psql', '-U', 'kutup', '-d', 'kutup', '-Atc', sql])
  if (!output) return { backups: 0, objects: 0, media: 0 }
  const [backups, objects, media] = output.split('|').map(Number)
  return { backups, objects, media }
}

test.describe('two-server continuous backup recovery', () => {
  test.skip(!hasSecondaryServer(), 'set E2E_SECONDARY_APP_ORIGIN for the federation topology')

  test('both account-local histories survive total browser loss and server restart', async ({ browser }) => {
    // Slow, plus up to eleven minutes for the contact lists' delayed writes.
    test.setTimeout(3 * 120_000 + 11 * 60_000)
    const tag = Date.now().toString(36)
    const alice = newAccount('backupalice', PASSWORD, 'primary')
    const bob = newAccount('backupbob', PASSWORD, 'secondary')
    const bobAddress = `${bob.username}@${serverDomain('secondary')}`
    const sourceA = await browser.newContext()
    const sourceB = await browser.newContext()
    recordSafeCheckpoint('two-server-recovery', 'source-contexts-created', { accounts: 2 })
    await registerAccount(sourceA, alice)
    await registerAccount(sourceB, bob)
    const pageA = await openChat(sourceA, 'primary')
    const pageB = await openChat(sourceB, 'secondary')
    await enableReadReceipts(pageB)

    await openDirectChat(pageA, bobAddress)
    const directOriginal = `direct-before-loss-a-${tag}`
    await say(pageA, directOriginal)
    await openConversationWith(pageB, alice.username)
    await arrives(pageB, directOriginal)
    await acceptRequest(pageB)
    await expect(message(pageA, directOriginal).getByTestId('chat-receipt-read')).toBeVisible({ timeout: 45_000 })

    const directReply = `direct-reply-${tag}`
    await replyTo(pageB, directOriginal, directReply)
    await arrives(pageA, directReply)
    await reactTo(pageB, directOriginal, '👍')
    await expect(reaction(pageA, directOriginal, '👍')).toHaveAttribute('data-count', '1', { timeout: 45_000 })
    const editedDirect = `direct-edited-${tag}`
    await editMessage(pageA, directOriginal, editedDirect)
    await arrives(pageB, editedDirect)

    const deletedDirect = `direct-deleted-${tag}`
    await say(pageA, deletedDirect)
    await arrives(pageB, deletedDirect)
    await deleteForEveryone(pageA, deletedDirect)
    await expect(message(pageB, deletedDirect)).toHaveCount(0, { timeout: 45_000 })
    await expect(pageB.getByTestId('chat-message-deleted')).toHaveCount(1)

    const directAttachment = `direct-protected-${tag}.txt`
    await sendAttachment(pageA, directAttachment, `direct protected media ${tag}`)
    await expect(attachmentIn(pageB, directAttachment)).toBeVisible({ timeout: 90_000 })

    await setDisappearing(pageA, 'thirtySeconds')
    await expect(pageB.getByTestId('chat-disappearing-timer'))
      .toHaveAccessibleName('New messages disappear after 30 seconds', { timeout: 45_000 })
    const expiredDirect = `direct-expired-${tag}`
    await say(pageA, expiredDirect)
    await arrives(pageB, expiredDirect)
    // Each side removes the message on its own 30-second timer. With four
    // Chat clients and two servers on a two-core runner a timer can run well
    // late, so the wait leaves room past 30 s rather than testing speed.
    await expect.poll(async () => ({
      alice: await message(pageA, expiredDirect).count(),
      bob: await message(pageB, expiredDirect).count(),
    }), { timeout: 120_000, intervals: [1_000, 2_000] }).toEqual({ alice: 0, bob: 0 })
    await setDisappearing(pageA, 'off')
    await expect(pageB.getByTestId('chat-disappearing-timer'))
      .toHaveAccessibleName('Disappearing messages are off', { timeout: 45_000 })

    // A group (docs/plans/pairwise-groups.md): text and replies, as slice 1
    // sends them; Alice and Bob are contacts from the chat above.
    const conversationId = await createGroup(pageA, bob.username)
    await acceptGroup(pageB, conversationId)

    const groupFromAlice = `group-before-loss-a-${tag}`
    await say(pageA, groupFromAlice)
    await arrives(pageB, groupFromAlice)
    const groupFromBob = `group-before-loss-b-${tag}`
    await say(pageB, groupFromBob)
    await arrives(pageA, groupFromBob)
    const groupReply = `group-reply-${tag}`
    await replyTo(pageB, groupFromAlice, groupReply)
    await arrives(pageA, groupReply)
    const aliceCursorBeforeFinalMutation = await backupCursor(pageA)
    const bobCursorBeforeFinalMutation = await backupCursor(pageB)
    const groupLast = `group-last-before-loss-${tag}`
    await say(pageA, groupLast)
    await arrives(pageB, groupLast)

    await waitForProtection(pageA, aliceCursorBeforeFinalMutation)
    await waitForProtection(pageB, bobCursorBeforeFinalMutation)
    recordSafeCheckpoint('two-server-recovery', 'both-accounts-protected', { accounts: 2 })

    const aliceOwn = backupFacts('postgres-a', alice.username)
    const bobOwn = backupFacts('postgres-b', bob.username)
    expect(aliceOwn).toMatchObject({ backups: 1 })
    expect(aliceOwn.objects).toBeGreaterThan(0)
    expect(aliceOwn.media).toBeGreaterThan(0)
    expect(bobOwn).toMatchObject({ backups: 1 })
    expect(bobOwn.objects).toBeGreaterThan(0)
    expect(bobOwn.media).toBeGreaterThan(0)
    expect(backupFacts('postgres-a', bob.username)).toEqual({ backups: 0, objects: 0, media: 0 })
    expect(backupFacts('postgres-b', alice.username)).toEqual({ backups: 0, objects: 0, media: 0 })
    recordSafeCheckpoint('two-server-recovery', 'account-locality-verified', {
      accounts: 2,
      media: aliceOwn.media + bobOwn.media,
      objects: aliceOwn.objects + bobOwn.objects,
    })
    // Each account's contact list has the other (docs/plans/chat-contacts-sync.md):
    // written at a random moment within ten minutes of the accept, so two
    // accounts accepting each other don't line up on their servers.
    await expect
      .poll(() => [contactListEntries('postgres-a', alice.username), contactListEntries('postgres-b', bob.username)], {
        timeout: 11 * 60_000,
        intervals: [10_000],
      })
      .toEqual([1, 1])
    recordSafeCheckpoint('two-server-recovery', 'contact-lists-written', { accounts: 2 })
    await sourceA.close()
    await sourceB.close()
    recordSafeCheckpoint('two-server-recovery', 'all-source-browsers-lost', { accounts: 2 })
    expect(backupRows('postgres-a', alice.username), 'closing Alice browser must not remove her account').toBe(1)
    expect(backupRows('postgres-b', bob.username), 'closing Bob browser must not remove his account').toBe(1)
    await restartHomeservers([
      { server: 'primary', postgres: 'postgres-a', username: alice.username },
      { server: 'secondary', postgres: 'postgres-b', username: bob.username },
    ])
    expect(backupRows('postgres-a', alice.username), 'Alice account must survive homeserver restart').toBe(1)
    expect(backupRows('postgres-b', bob.username), 'Bob account must survive homeserver restart').toBe(1)
    recordSafeCheckpoint('two-server-recovery', 'homeservers-restarted', { accounts: 2 })

    const transferRequests: string[] = []
    const mediaGets = { a: [] as string[], b: [] as string[] }
    const watch = (context: BrowserContext, side: 'a' | 'b') => {
      void context.route('**/api/chat/media/objects/*', (route) => route.fulfill({ status: 404 }))
      context.on('request', (request) => {
        if (request.url().includes('history-transfer')) transferRequests.push(request.url())
        const path = new URL(request.url()).pathname
        if (request.method() === 'GET' && path.includes('/chat/backup/media/')) mediaGets[side].push(path)
      })
    }
    const cleanA = await browser.newContext()
    const cleanB = await browser.newContext()
    watch(cleanA, 'a')
    watch(cleanB, 'b')
    await signIn(cleanA, alice)
    await signIn(cleanB, bob)
    const restoredA = await openChat(cleanA, 'primary')
    const restoredB = await openChat(cleanB, 'secondary')
    await openConversationWith(restoredA, bob.username)
    await openConversationWith(restoredB, alice.username)
    const aliceCursorBeforeFreshMessages = await backupCursor(restoredA)
    const bobCursorBeforeFreshMessages = await backupCursor(restoredB)
    for (const page of [restoredA, restoredB]) {
      await expect(message(page, editedDirect)).toBeVisible({ timeout: 45_000 })
      await expect(message(page, directReply).getByTestId('chat-reply-context')).toContainText(editedDirect)
      await expect(reaction(page, editedDirect, '👍')).toHaveAttribute('data-count', '1')
      await expect(message(page, deletedDirect)).toHaveCount(0)
      await expect(message(page, expiredDirect)).toHaveCount(0)
      await expect(attachmentIn(page, directAttachment)).toBeVisible()
    }
    await expect(message(restoredA, editedDirect).getByTestId('chat-receipt-read')).toBeVisible()
    expect(mediaGets).toEqual({ a: [], b: [] })
    const directProtectedDownload = restoredB.waitForResponse((response) => {
      const path = new URL(response.url()).pathname
      return response.request().method() === 'GET' && path.includes('/api/chat/backup/media/') && response.ok()
    })
    await restoredB.getByRole('button', { name: `Download ${directAttachment} into Kutup` }).click()
    await directProtectedDownload
    await expect(restoredB.getByRole('button', { name: `${directAttachment} is available in Kutup` }))
      .toBeVisible({ timeout: 45_000 })

    // The group's history comes back with the account's (read-only until
    // the group itself follows to new devices).
    for (const page of [restoredA, restoredB]) {
      await page.getByTestId(`chat-group-${conversationId}`).click()
      await expect(message(page, groupFromAlice)).toBeVisible({ timeout: 45_000 })
      await expect(message(page, groupFromBob)).toBeVisible()
      await expect(message(page, groupReply).getByTestId('chat-reply-context')).toContainText(groupFromAlice)
      await expect(message(page, groupLast)).toBeVisible()
    }
    recordSafeCheckpoint('two-server-recovery', 'direct-and-group-restored', { accounts: 2, media: 1 })
    expect(transferRequests).toEqual([])
    expect(backupFacts('postgres-a', alice.username).objects).toBeGreaterThan(0)
    expect(backupFacts('postgres-b', bob.username).objects).toBeGreaterThan(0)
    expect(backupFacts('postgres-a', bob.username)).toEqual({ backups: 0, objects: 0, media: 0 })
    expect(backupFacts('postgres-b', alice.username)).toEqual({ backups: 0, objects: 0, media: 0 })

    // With no device left to link from, each clean browser started its
    // account's Chat over (a new identity), which dropped the lost devices;
    // each side saw the other's safety number change once.
    for (const page of [restoredA, restoredB]) {
      await openSettings(page, 'Linked devices')
      await expect(page.getByTestId('chat-devices-list').locator('li')).toHaveCount(1, { timeout: 45_000 })
      await expect(page.locator('[data-testid^="chat-device-revoke-"]')).toHaveCount(0)
      await openChats(page)
    }

    await openConversationWith(restoredA, bob.username)
    await openConversationWith(restoredB, alice.username)
    const directAfterRestore = `direct-after-restore-${tag}`
    await say(restoredA, directAfterRestore)
    await arrives(restoredB, directAfterRestore)
    // Their contact states came back from their contact lists: still
    // contacts, no request to accept again, and one invites the other.
    await expect(restoredB.getByRole('button', { name: 'Accept', exact: true })).toHaveCount(0)
    const answerAfterRestore = `answer-after-restore-${tag}`
    await say(restoredB, answerAfterRestore)
    await arrives(restoredA, answerAfterRestore)

    const freshConversationId = await createGroup(restoredA, bob.username)
    await acceptGroup(restoredB, freshConversationId)
    const groupAfterRestore = `group-after-restore-${tag}`
    await say(restoredB, groupAfterRestore)
    await arrives(restoredA, groupAfterRestore)
    await waitForProtection(restoredA, aliceCursorBeforeFreshMessages)
    await waitForProtection(restoredB, bobCursorBeforeFreshMessages)
    await cleanA.close()
    await cleanB.close()
    recordSafeCheckpoint('two-server-recovery', 'post-restore-messaging-protected', {
      accounts: 2,
      conversations: 2,
    })
  })
})
