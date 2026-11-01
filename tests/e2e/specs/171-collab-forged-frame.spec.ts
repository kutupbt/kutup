import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { backFromEditor, createFolder, createNote, item, itemAction, noteLive, noteText, openItem, openNote, typeAtEnd } from '../fixtures/drive'

const PASSWORD = 'Deneme123*ForgedFramePassword'

// Recipients verify senders (docs/plans/one-device-list.md §8, slice 3): a
// home that relays a frame its sender's devices didn't sign (here, every
// frame to one tab with its signature changed in transit) has it dropped by
// the recipient, which says so once. The edit still reaches the home's log
// from its real sender; only the forged copies are refused.
test('a frame its sender did not sign is not applied, and the editor says so', async ({ browser }) => {
  test.slow()
  const context = await browser.newContext()
  const account = newAccount('forged171', PASSWORD)
  await registerAccount(context, account)
  const drive = await openDrive(context)
  await createNote(drive)
  const url = drive.url()
  await drive.close()

  const a = await openNote(context, url)
  const b = await context.newPage()
  let forge = false
  await b.routeWebSocket(/\/collab\/ws/, (socket) => {
    const server = socket.connectToServer()
    server.onMessage((message) => {
      if (forge && typeof message !== 'string') {
        // The signature is the frame's last 64 bytes: one bit of it.
        const bytes = Buffer.from(message)
        bytes[bytes.length - 1] ^= 1
        socket.send(bytes)
      } else {
        socket.send(message)
      }
    })
    socket.onMessage((message) => server.send(message))
  })
  await b.goto(url)
  await noteLive(b)

  // Frames as their sender signed them are applied.
  await typeAtEnd(a, ' genuine-edit')
  await expect.poll(() => noteText(b), { timeout: 30_000 }).toContain('genuine-edit')

  // Forged in transit: never applied, and said once.
  forge = true
  await typeAtEnd(a, ' forged-edit')
  await expect(b.getByText(/couldn't be verified and weren't applied/)).toBeVisible({ timeout: 30_000 })
  await b.waitForTimeout(2_000)
  expect(await noteText(b)).not.toContain('forged-edit')
  expect(await noteText(a)).toContain('forged-edit')
  await context.close()
})

/** Where the packed frame starts in a delivered one: after its sender (a
 * length-prefixed server name and the 16-byte account id). */
function frameStart(delivered: Buffer): number {
  return 2 + delivered.readUInt16BE(0) + 16
}

/** A delivered frame's device id (the packed frame's bytes 36..40). */
const DEVICE_AT = 36

// The other two ways a home can relay a frame its sender didn't sign: under
// a device the sender's account doesn't list (the recipient fetches the
// account's current list before refusing it), and another account's
// genuinely signed frame named as this account's (a valid signature, but
// not by a key this account lists). Both are refused and said; the genuine
// edits around them still arrive.
test('a frame from an unlisted device, or signed by another account, is refused', async ({ browser }) => {
  test.slow()
  const tag = Date.now()
  const alice = newAccount('unlisted171a', PASSWORD)
  const bob = newAccount('unlisted171b', PASSWORD)
  const contextA = await browser.newContext()
  const contextB = await browser.newContext()
  await registerAccount(contextA, alice)
  await registerAccount(contextB, bob)

  const drive = await openDrive(contextA)
  const folder = `forged-${tag}`
  await createFolder(drive, folder)
  await openItem(drive, folder)
  await expect(drive.getByRole('navigation', { name: 'Breadcrumb' })).toContainText(folder, { timeout: 30_000 })
  const note = await createNote(drive)
  const noteUrl = drive.url()
  await noteLive(drive)
  await typeAtEnd(drive, ` SEED-${tag}`)
  await backFromEditor(drive)
  await drive.getByRole('link', { name: 'My files', exact: true }).first().click()
  await expect(item(drive, folder)).toBeVisible({ timeout: 30_000 })
  let shared = 0
  drive.on('response', (response) => {
    const path = new URL(response.url()).pathname
    if (/^\/api\/collections\/[^/]+\/share$/.test(path) && response.request().method() === 'POST') shared = response.status()
  })
  await itemAction(drive, folder, 'Share')
  const dialog = drive.getByRole('dialog')
  await dialog.getByLabel('Kutup address').fill(bob.address)
  await dialog.getByLabel('Can add and edit files').check()
  await dialog.getByRole('button', { name: 'Share', exact: true }).click()
  await expect.poll(() => shared, { timeout: 30_000 }).toBe(201)
  await drive.keyboard.press('Escape')
  await drive.close()

  // Two more tabs of Alice's behind a home that rewrites what it relays.
  // Alice's own frames are the only ones in the log so far, so the first
  // one either tab is sent names her.
  let alicePrefix: Buffer | null = null
  async function relayedBy(rewrite: (delivered: Buffer, start: number) => Buffer | null) {
    const page = await contextA.newPage()
    await page.routeWebSocket(/\/collab\/ws/, (socket) => {
      const server = socket.connectToServer()
      server.onMessage((message) => {
        if (typeof message === 'string') return socket.send(message)
        const delivered = Buffer.from(message)
        const start = frameStart(delivered)
        alicePrefix ??= Buffer.from(delivered.subarray(0, start))
        socket.send(rewrite(delivered, start) ?? delivered)
      })
      socket.onMessage((message) => server.send(message))
    })
    await page.goto(noteUrl)
    await noteLive(page)
    await expect.poll(() => noteText(page), { timeout: 30_000 }).toContain(`SEED-${tag}`)
    return page
  }
  let unlist = false
  const unlisted = await relayedBy((delivered, start) => {
    if (!unlist || !alicePrefix || !delivered.subarray(0, start).equals(alicePrefix)) return null
    const forged = Buffer.from(delivered)
    forged.writeUInt32BE(4242, start + DEVICE_AT)
    return forged
  })
  // Armed once Bob is in (the notice is a toast: one raised by his joining
  // would be gone before the check).
  let relabel = false
  const relabelled = await relayedBy((delivered, start) => {
    if (!relabel || !alicePrefix || delivered.subarray(0, start).equals(alicePrefix)) return null
    // Bob's frame, as Alice's: his device's valid signature, her name.
    return Buffer.concat([alicePrefix, delivered.subarray(start)])
  })

  // Bob opens the shared note; his edits reach Alice's plain tab only.
  const b = await openDrive(contextB, 'primary', '/shared')
  await expect.poll(
    async () => {
      if ((await item(b, folder).count()) > 0) return true
      await b.reload()
      return false
    },
    { timeout: 60_000, intervals: [1_000, 2_000] },
  ).toBe(true)
  await openItem(b, folder)
  await expect(item(b, note)).toBeVisible({ timeout: 60_000 })
  await openItem(b, note)
  await noteLive(b)
  const a = await openNote(contextA, noteUrl)
  relabel = true
  await typeAtEnd(b, ` FROM-B-${tag}`)
  await expect.poll(() => noteText(a), { timeout: 30_000 }).toContain(`FROM-B-${tag}`)
  await expect(relabelled.getByText(/couldn't be verified and weren't applied/)).toBeVisible({ timeout: 30_000 })
  expect(await noteText(relabelled)).not.toContain(`FROM-B-${tag}`)

  // Alice's own edits, relayed from a device her account doesn't list.
  await typeAtEnd(a, ` GENUINE-A-${tag}`)
  await expect.poll(() => noteText(unlisted), { timeout: 30_000 }).toContain(`GENUINE-A-${tag}`)
  await expect.poll(() => noteText(relabelled), { timeout: 30_000 }).toContain(`GENUINE-A-${tag}`)
  unlist = true
  await typeAtEnd(a, ` UNLISTED-A-${tag}`)
  await expect(unlisted.getByText(/couldn't be verified and weren't applied/)).toBeVisible({ timeout: 30_000 })
  await unlisted.waitForTimeout(2_000)
  expect(await noteText(unlisted)).not.toContain(`UNLISTED-A-${tag}`)
  await expect.poll(() => noteText(b), { timeout: 30_000 }).toContain(`UNLISTED-A-${tag}`)

  await contextA.close()
  await contextB.close()
})
