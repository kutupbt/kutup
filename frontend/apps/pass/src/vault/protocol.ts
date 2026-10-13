// Messages between the page and the Kutup Pass worker (./worker.ts).

import type { Op } from './types'

type Calls =
  | { call: 'create'; name: string; password: string | null; keyFile: Uint8Array | null; now: number }
  | { call: 'open'; contents: Uint8Array; password: string | null; passwordHash: Uint8Array | null; keyFile: Uint8Array | null }
  | { call: 'view'; handle: number }
  | { call: 'apply'; handle: number; op: Op; now: number }
  | { call: 'history'; handle: number; entryId: string }
  | { call: 'attachment'; handle: number; entryId: string; name: string }
  | { call: 'otp'; handle: number; entryId: string; now: number }
  | { call: 'save'; handle: number }
  | {
      call: 'merge'
      handle: number
      base: Uint8Array | null
      theirs: Uint8Array
      theirsPassword: string | null
      theirsKeyFile: Uint8Array | null
    }
  | { call: 'changeKey'; handle: number; password: string | null; keyFile: Uint8Array | null; now: number }
  | { call: 'close'; handle: number }
  | { call: 'keepKey'; handle: number; masterKey: Uint8Array; binding: string; fileId: string; revision: number; generated: boolean }
  | { call: 'openKept'; envelope: string; masterKey: Uint8Array; binding: string; fileId: string }
  | { call: 'importPreview'; contents: Uint8Array; provider: string | null }
  | { call: 'importFormats' }

export type Request = Calls & { id: number }
export type Call = Calls

export type Response = { id: number; ok: true; result: unknown } | { id: number; ok: false; message: string }
