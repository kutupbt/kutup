import { expect, test } from '@playwright/test'
import { newAccount, openDrive, registerAccount } from '../fixtures/apps'
import { createNote, noteLive, noteText, openNote, typeAtEnd } from '../fixtures/drive'

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
