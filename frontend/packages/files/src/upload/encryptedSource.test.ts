// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { DRIVE_BLOCK_SIZE, generateKey, newDriveBlockEncryptor, newRevisionId, openDriveFile } from '@kutup/crypto'
import { EncryptedFileSource, type PlaintextSource, type SealedTail } from './encryptedSource'

const signer = { masterKey: new Uint8Array(32).fill(5), accountId: '22222222-2222-4222-8222-222222222222' }

function plaintext(size: number): PlaintextSource & { reads: number } {
  // A plain loop: Uint8Array.from over an array-like with a callback takes
  // seconds for 10 MiB.
  const bytes = new Uint8Array(size)
  for (let i = 0; i < size; i++) bytes[i] = (i * 7 + 3) & 0xff
  const source = {
    size,
    reads: 0,
    read: async (start: number, end: number) => {
      source.reads++
      return bytes.slice(start, end)
    },
  }
  return source
}

/** A revision of `size` bytes: sources over it, and its key and binding to open what they give. */
async function setup(size: number) {
  const fileKey = await generateKey()
  const context = { fileId: crypto.randomUUID(), revisionId: newRevisionId(), generation: 1 }
  const open = () => newDriveBlockEncryptor(fileKey, context, size)
  const source = async (options: { input?: ReturnType<typeof plaintext>; tail?: SealedTail; onTail?: (tail: SealedTail) => Promise<void> } = {}) => {
    const input = options.input ?? plaintext(size)
    return { input, source: new EncryptedFileSource(input, await open(), { open, signer, tail: options.tail, onTail: options.onTail }) }
  }
  const opens = (object: Uint8Array, content: SealedTail['content']) =>
    openDriveFile(object, fileKey, { fileId: context.fileId, generation: 1 }, content, size)
  return { source, opens, revisionId: context.revisionId }
}

/** Everything from `start` to the end, in ranges of `step`. */
async function readFrom(source: EncryptedFileSource, start: number, step: number): Promise<Uint8Array> {
  const read: Uint8Array[] = []
  let done = false
  for (let at = start; !done; at += step) {
    const slice = await source.bytes(at, at + step)
    read.push(slice.bytes)
    done = slice.done
  }
  return new Uint8Array(Buffer.concat(read))
}

// Several 4 MiB blocks are built and sealed here; that takes a few seconds.
vi.setConfig({ testTimeout: 60_000 })

const PATCH = 2 * (DRIVE_BLOCK_SIZE + 40)

describe('EncryptedFileSource', () => {
  for (const size of [0, 10, DRIVE_BLOCK_SIZE, DRIVE_BLOCK_SIZE + 1, 2 * DRIVE_BLOCK_SIZE + 123]) {
    it(`gives tus a ${size}-byte file's whole revision, which opens against its commitment`, async () => {
      const { source, opens, revisionId } = await setup(size)
      const tails: SealedTail[] = []
      const { source: s } = await source({ onTail: async (tail) => void tails.push(tail) })
      const object = await readFrom(s, 0, PATCH)
      expect(object.length).toBe(s.size)
      expect(tails).toHaveLength(1)
      expect(s.content).toEqual(tails[0].content)
      expect(s.content?.revisionId).toBe(revisionId)
      expect(await opens(object, tails[0].content)).toEqual(await plaintext(size).read(0, size))
    })
  }

  it('resumes after a reload at a block boundary with the same bytes', async () => {
    const size = 3 * DRIVE_BLOCK_SIZE + 5
    const { source, opens } = await setup(size)
    let kept: SealedTail | undefined
    const { source: s } = await source({ onTail: async (tail) => void (kept = tail) })
    const whole = await readFrom(s, 0, PATCH)
    // The same file chosen again after a reload: a new source, the tail kept.
    const { source: again } = await source({ tail: kept })
    const at = 48 + 2 * (DRIVE_BLOCK_SIZE + 40)
    const rest = await readFrom(again, at, PATCH)
    expect(Buffer.from(rest).equals(Buffer.from(whole.subarray(at)))).toBe(true)
    expect(await opens(whole, kept!.content)).toHaveLength(size)
  })

  it('resumes inside a block, sealing it again from its start, and sends from the exact offset', async () => {
    const size = 2 * DRIVE_BLOCK_SIZE + 77
    const { source, opens } = await setup(size)
    let kept: SealedTail | undefined
    // The first run stopped inside block 1, before the tail was made.
    const { source: s } = await source({ onTail: async (tail) => void (kept = tail) })
    const at = 48 + (DRIVE_BLOCK_SIZE + 40) + 12345
    const sent = (await s.bytes(0, at)).bytes
    expect(kept).toBeUndefined()
    s.close()
    const { source: again } = await source({ onTail: async (tail) => void (kept = tail) })
    const rest = await readFrom(again, at, PATCH)
    const object = new Uint8Array(Buffer.concat([sent, rest]))
    expect(object.length).toBe(again.size)
    expect(await opens(object, kept!.content)).toHaveLength(size)
  })

  it('resumes inside the tail from the kept tail, never making another', async () => {
    const size = 100
    const { source, opens } = await setup(size)
    let kept: SealedTail | undefined
    const { source: s } = await source({ onTail: async (tail) => void (kept = tail) })
    const whole = await readFrom(s, 0, PATCH)
    const tailAt = whole.length - 20
    const made = vi.fn(async () => {})
    const { source: again } = await source({ tail: kept, onTail: made })
    const rest = await again.bytes(tailAt, whole.length)
    expect(Buffer.from(rest.bytes).equals(Buffer.from(whole.subarray(tailAt)))).toBe(true)
    expect(made).not.toHaveBeenCalled()
    expect(await opens(whole, kept!.content)).toHaveLength(size)
  })

  it('reads nothing again for a retried range, and starts over for one before those it kept', async () => {
    const size = 6 * DRIVE_BLOCK_SIZE
    const { source } = await setup(size)
    const { source: s, input } = await source()
    const at = 48 + 4 * (DRIVE_BLOCK_SIZE + 40)
    const first = await s.bytes(at, at + PATCH)
    const reads = input.reads
    expect((await s.bytes(at, at + PATCH)).bytes).toEqual(first.bytes)
    expect(input.reads).toBe(reads)
    const early = await s.bytes(0, PATCH)
    const { source: fresh } = await source()
    expect(early.bytes).toEqual((await fresh.bytes(0, PATCH)).bytes)
  })

  it('gives tus a Blob, whose size tus reads, down to the last range', async () => {
    const { source } = await setup(DRIVE_BLOCK_SIZE)
    const { source: s } = await source()
    const last = await s.slice(PATCH / 2, PATCH)
    expect(last.value).toBeInstanceOf(Blob)
    expect(last.value.size).toBe(s.size - PATCH / 2)
    expect(last.done).toBe(true)
  })

  it('refuses a file that changed size while it was read', async () => {
    const { source } = await setup(DRIVE_BLOCK_SIZE + 10)
    const shrunk = { ...plaintext(DRIVE_BLOCK_SIZE + 10), read: async () => new Uint8Array(3) }
    const { source: s } = await source({ input: shrunk as unknown as ReturnType<typeof plaintext> })
    await expect(s.bytes(0, PATCH)).rejects.toThrow(/changed/)
  })
})
