// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([import('node:fs/promises'), import('../../../../wasm/crypto-wasm/kutup_crypto_wasm.js')])
  const wasm = await readFile(new URL('../../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { testRoots } from '@kutup/crypto/accountRoots.testing'
import { newRevisionId, sealDriveFile, type ContentCommitment } from '@kutup/crypto/driveBlocks'
import { BlockObjectReader, answerOnPort } from './core'
import type { BlockReaderSettings, StreamChunkAnswer } from './protocol'

const B = 4 * 1024 * 1024
const fileKey = new Uint8Array(32).fill(0x21)
const fileId = '11111111-1111-4111-8111-111111111111'
const signer = { identityRoot: testRoots(0x09).identityRoot, accountId: '22222222-2222-4222-8222-222222222222', incarnationId: '05'.repeat(32) }
const settings: BlockReaderSettings = { cacheBlocks: 3, readaheadBlocks: 0, responseMaxBytes: 5 * 1024 * 1024 }

function pattern(length: number, seed = 1): Uint8Array {
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) out[i] = (i * 31 + seed) & 0xff
  return out
}

/** A server answering Range over `object`, logging what it was asked. */
function server(object: Uint8Array, revisionId: string) {
  const asked: string[] = []
  const fetch = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
    const range = new Headers(init?.headers).get('Range') ?? ''
    asked.push(range)
    const match = /^bytes=(\d+)-(\d+)$/.exec(range)
    if (!match) return new Response('no range', { status: 400 })
    const start = Number(match[1])
    const end = Math.min(Number(match[2]), object.length - 1)
    if (start >= object.length) return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${object.length}` } })
    return new Response(object.slice(start, end + 1), {
      status: 206,
      headers: { 'Content-Range': `bytes ${start}-${end}/${object.length}`, 'x-kutup-revision': revisionId },
    })
  })
  return { fetch: fetch as unknown as typeof globalThis.fetch, asked }
}

async function sealed(size: number) {
  const revisionId = newRevisionId()
  const plain = pattern(size)
  const object = await sealDriveFile(plain, fileKey, { fileId, revisionId, generation: 1 }, signer)
  return { plain, revisionId, bytes: object.bytes, content: object.content }
}

function target(content: ContentCommitment, size: number) {
  return { family: 'drive' as const, url: 'https://drive.kutup.test/api/files/x/download', fileKey, expected: { fileId, generation: 1, content, size } }
}

describe('the block reader', () => {
  it('opens the manifest against the committed digest before it fetches a block', async () => {
    const object = await sealed(2 * B + 17)
    const other = await sealed(2 * B + 17)
    const { fetch, asked } = server(object.bytes, object.revisionId)
    // The commitment of other content under another revision: refused at the manifest.
    await expect(BlockObjectReader.open(target({ revisionId: object.revisionId, manifestSha256: other.content.manifestSha256 }, object.plain.length), settings, { fetch, token: () => 't' })).rejects.toThrow()
    // The header, the trailer and the manifest: nothing by block.
    expect(asked).toHaveLength(3)
    expect(asked[0]).toBe('bytes=0-47')
    expect(asked[1]).toBe(`bytes=${object.bytes.length - 12}-${object.bytes.length - 1}`)
    // A wrong size is refused the same way.
    await expect(BlockObjectReader.open(target(object.content, object.plain.length + 1), settings, { fetch, token: () => 't' })).rejects.toThrow()
    expect(asked).toHaveLength(6)
  })

  it('sends the bearer token, and none for a public link', async () => {
    const object = await sealed(10)
    const { fetch } = server(object.bytes, object.revisionId)
    await BlockObjectReader.open(target(object.content, 10), settings, { fetch, token: () => 'secret' })
    expect(new Headers((fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0][1].headers).get('Authorization')).toBe('Bearer secret')
    await BlockObjectReader.open(target(object.content, 10), settings, { fetch, token: () => '' })
    expect(new Headers((fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[3][1].headers).has('Authorization')).toBe(false)
  })

  it('reads every block back, the last one shorter, each fetched once while cached', async () => {
    const object = await sealed(2 * B + 17)
    const { fetch, asked } = server(object.bytes, object.revisionId)
    const reader = await BlockObjectReader.open(target(object.content, object.plain.length), settings, { fetch, token: () => '' })
    expect(reader.opened).toMatchObject({ fileId, revisionId: object.revisionId, size: 2 * B + 17, blockCount: 3, blockSize: B, signer: { accountId: signer.accountId, incarnationId: signer.incarnationId } })
    expect(await reader.block(0)).toEqual(object.plain.subarray(0, B))
    expect(await reader.block(1)).toEqual(object.plain.subarray(B, 2 * B))
    const last = await reader.block(2)
    expect(last.length).toBe(17)
    expect(last).toEqual(object.plain.subarray(2 * B))
    const fetched = asked.length
    await reader.block(1)
    expect(asked.length).toBe(fetched)
    reader.close()
    await expect(reader.block(0)).rejects.toThrow()
  })

  it('refuses a corrupted block and still serves the others', async () => {
    const object = await sealed(2 * B + 17)
    const corrupted = object.bytes.slice()
    // A byte inside block 1's sealed bytes.
    corrupted[48 + (B + 40) + 1000] ^= 0x01
    const { fetch } = server(corrupted, object.revisionId)
    const reader = await BlockObjectReader.open(target(object.content, object.plain.length), settings, { fetch, token: () => '' })
    await expect(reader.block(1)).rejects.toThrow()
    expect(await reader.block(0)).toEqual(object.plain.subarray(0, B))
    expect(await reader.block(2)).toEqual(object.plain.subarray(2 * B))
    // As a stream answer: an error, never bytes.
    const { answer } = await reader.answer({ start: B + 5, end: null }, 'video/mp4').catch((error: Error) => ({ answer: { kind: 'thrown', message: error.message } }))
    expect(answer.kind).toBe('thrown')
  })

  it('answers a stream range to the end of its block, a suffix from the end, and 416 past it', async () => {
    const object = await sealed(2 * B + 17)
    const { fetch } = server(object.bytes, object.revisionId)
    const reader = await BlockObjectReader.open(target(object.content, object.plain.length), settings, { fetch, token: () => '' })
    const bytesOf = (answer: StreamChunkAnswer) => (answer.kind === 'bytes' ? new Uint8Array(answer.bytes) : null)

    const probe = (await reader.answer({ start: 0, end: 1 }, 'video/mp4')).answer
    expect(probe).toMatchObject({ v: 1, kind: 'bytes', start: 0, total: 2 * B + 17, mimeType: 'video/mp4' })
    expect(bytesOf(probe)).toEqual(object.plain.subarray(0, 2))

    const across = (await reader.answer({ start: B - 10, end: B + 10 }, 'video/mp4')).answer
    expect(bytesOf(across)).toEqual(object.plain.subarray(B - 10, B))

    const tail = (await reader.answer({ suffix: 5 }, 'video/mp4')).answer
    expect(tail).toMatchObject({ start: 2 * B + 12 })
    expect(bytesOf(tail)).toEqual(object.plain.subarray(2 * B + 12))

    expect((await reader.answer({ start: 2 * B + 17, end: null }, 'video/mp4')).answer).toEqual({ v: 1, kind: 'unsatisfiable', total: 2 * B + 17 })

    // On a port, as the service worker reads it.
    const channel = new MessageChannel()
    const got = new Promise<StreamChunkAnswer>((resolve) => {
      channel.port2.onmessage = (event) => resolve(event.data as StreamChunkAnswer)
    })
    await answerOnPort(reader, channel.port1, { start: 2 * B, end: null }, 'audio/mpeg')
    expect(bytesOf(await got)).toEqual(object.plain.subarray(2 * B))
    channel.port2.close()
  })

  it('reads ahead the next block', async () => {
    const object = await sealed(2 * B + 17)
    const { fetch, asked } = server(object.bytes, object.revisionId)
    const reader = await BlockObjectReader.open(target(object.content, object.plain.length), { ...settings, readaheadBlocks: 1 }, { fetch, token: () => '' })
    await reader.block(0)
    await vi.waitFor(() => expect(asked).toContain(`bytes=${48 + (B + 40)}-${48 + 2 * (B + 40) - 1}`))
    reader.close()
  })

  it('refuses an object whose length the server misstates', async () => {
    const object = await sealed(100)
    const longer = new Uint8Array(object.bytes.length + 1)
    longer.set(object.bytes)
    const { fetch } = server(longer, object.revisionId)
    await expect(BlockObjectReader.open(target(object.content, 100), settings, { fetch, token: () => '' })).rejects.toThrow()
  })
})
