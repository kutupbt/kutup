// What the Kutup Pass WASM module speaks (crates/kutup-pass: `view` and
// `edit`); the Rust types are the source of truth.

export interface FieldView {
  key: string
  value: string
  /** Kept protected by KeePass apps, and shown hidden. */
  protected: boolean
}

export interface AttachmentView {
  name: string
  size: number
}

export interface AutoTypeView {
  enabled: boolean
  defaultSequence: string | null
  associations: { window: string; sequence: string }[]
}

export interface EntryView {
  id: string
  groupId: string
  /** The standard fields first, then custom ones by name. */
  fields: FieldView[]
  tags: string[]
  icon: number | null
  hasCustomIcon: boolean
  /** Its picture in `VaultView.customIcons`, when a browser can show it. */
  customIcon: string | null
  foregroundColor: string | null
  backgroundColor: string | null
  overrideUrl: string
  qualityCheck: boolean
  expires: boolean
  expiry: string | null
  created: string | null
  modified: string | null
  accessed: string | null
  attachments: AttachmentView[]
  autoType: AutoTypeView | null
  historyCount: number
  /** Fields a merge found changed on two devices: one value here, the other in history. */
  review: string[]
  inRecycleBin: boolean
}

/** A field shown resolved (references and placeholders). */
export interface ResolvedField {
  key: string
  value: string
  /** It comes from another entry ({REF:…}). */
  fromReference: boolean
}

export interface GroupView {
  id: string
  parentId: string | null
  depth: number
  name: string
  notes: string
  icon: number | null
  hasCustomIcon: boolean
  /** Its picture in `VaultView.customIcons`, when a browser can show it. */
  customIcon: string | null
  tags: string[]
  expires: boolean
  expiry: string | null
  isRecycleBin: boolean
  inRecycleBin: boolean
}

export interface VaultView {
  name: string
  description: string
  defaultUserName: string
  rootGroupId: string
  recycleBinId: string | null
  recycleBinEnabled: boolean
  historyMaxItems: number | null
  historyMaxSize: number | null
  /** The key derivation; null for one Kutup Pass can't set. */
  kdf: KdfInput | null
  /** Whether the file is compressed (GZip). */
  compression: boolean
  groups: GroupView[]
  entries: EntryView[]
  /** The vault's own pictures (KeePass custom icons) a browser can show. */
  customIcons: CustomIconView[]
}

export interface CustomIconView {
  id: string
  /** From the bytes: PNG, JPEG, GIF, WebP, ICO or BMP. */
  mime: string
  /** Base64. */
  data: string
}

export interface EntryInput {
  fields: FieldView[]
  tags: string[]
  icon?: number | null
  foregroundColor?: string | null
  backgroundColor?: string | null
  overrideUrl?: string
  qualityCheck?: boolean
  expires?: boolean
  expiry?: string | null
}

export type Op =
  | { op: 'createEntry'; groupId: string; entry: EntryInput }
  | { op: 'updateEntry'; id: string; entry: EntryInput }
  | { op: 'deleteEntry'; id: string }
  | { op: 'moveEntry'; id: string; groupId: string }
  /** Several entries to one group, as one edit (not into the recycle bin). */
  | { op: 'moveEntries'; ids: string[]; groupId: string }
  /** Several entries into the recycle bin, or for good from inside it or with it off. */
  | { op: 'deleteEntries'; ids: string[] }
  /** Entries out of the recycle bin, each back to the group it was in (or the top group). */
  | { op: 'restoreEntries'; ids: string[] }
  /** Several entries into the recycle bin and nothing else: refused when it is off (a drag never deletes for good). */
  | { op: 'recycleEntries'; ids: string[] }
  | { op: 'restoreHistory'; id: string; index: number }
  /** Copies beside each entry (KeePassXC's Clone); returns the first copy's id. */
  | { op: 'cloneEntries'; ids: string[]; titleSuffix: string | null; history: boolean; references?: boolean }
  /** Deletes history items (indexes oldest first; null: all), remembered so a merge doesn't bring them back. */
  | { op: 'deleteHistory'; id: string; indexes: number[] | null }
  | { op: 'clearReview'; id: string }
  | { op: 'addAttachment'; entryId: string; name: string; data: string }
  | { op: 'removeAttachment'; entryId: string; name: string }
  | { op: 'renameAttachment'; entryId: string; name: string; newName: string }
  /** A PNG (base64) as the entry's own picture, or null for the default icon. */
  | { op: 'setEntryIcon'; id: string; data: string | null; builtin?: number }
  | { op: 'setGroupIcon'; id: string; data: string | null; builtin?: number }
  | { op: 'createGroup'; parentId: string; name: string }
  | { op: 'updateGroup'; id: string; name: string; notes?: string; icon?: number | null }
  | { op: 'deleteGroup'; id: string }
  /** A group into the recycle bin and nothing else: refused when it is off (a drag never deletes for good). */
  | { op: 'recycleGroup'; id: string }
  /** Not into the recycle bin (that is a delete), never the bin itself; out of the bin it restores there. */
  | { op: 'moveGroup'; id: string; parentId: string }
  /** Groups out of the recycle bin, each with what it holds, back to the group it was in (or the top group). */
  | { op: 'restoreGroups'; ids: string[] }
  | { op: 'emptyRecycleBin' }
  | { op: 'importCsv'; data: string; provider: string | null; groupName: string }
  /** The bin and the history limits are kept when absent; lowering a limit trims every history at once. */
  | { op: 'updateVault'; name: string; description?: string; defaultUserName?: string; recycleBinEnabled?: boolean; history?: HistoryLimits }
  /** The key derivation and compression, refused below the server's minimums. */
  | { op: 'setVaultConfig'; kdf: KdfInput; compression: boolean; minimums: KdfMinimums }

/** History kept per entry; null is no limit. */
export interface HistoryLimits {
  maxItems: number | null
  /** Bytes. */
  maxSize: number | null
}

/** A key derivation (kutup_pass::edit::KdfInput). */
export type KdfInput =
  | { kind: 'argon2id'; memoryMib: number; iterations: number; parallelism: number }
  | { kind: 'argon2d'; memoryMib: number; iterations: number; parallelism: number }
  | { kind: 'aesKdf'; rounds: number }

/** The weakest key derivation this server lets a vault be set to (`passKdfMinimums`). */
export interface KdfMinimums {
  argon2MemoryMib: number
  argon2Iterations: number
  aesKdfRounds: number
}

export interface Applied {
  id: string | null
  changed: boolean
}

export interface Conflict {
  id: string
  title: string | null
  fields: string[]
}

export interface MergeReport {
  added: string[]
  updated: string[]
  conflicts: Conflict[]
  restored: string[]
  deleted: string[]
  moved: string[]
  groupsAdded: string[]
  groupsUpdated: string[]
  groupsDeleted: string[]
  groupsRestored: string[]
  groupConflicts: Conflict[]
  metadataConflicts: string[]
}

export interface MergeOutcome {
  report: MergeReport
  differsFromTheirs: boolean
  /** Theirs opened with this vault's own key: a key change it holds is in Drive already. */
  theirsUnderCurrentKey: boolean
}

export interface ImportFormat {
  id: string
  name: string
}

export interface ImportPreview {
  provider: string
  providerName: string
  count: number
  groups: string[]
  sample: { title: string; username: string; url: string; group: string }[]
  /** What would not be imported: "kind: title". */
  skipped: string[]
  warnings: string[]
}

export interface ImportFailure {
  error: 'empty' | 'tooLarge' | 'unreadable' | 'unknownFormat' | 'missingColumns' | 'tooMany'
  detail: string
}

export interface OtpView {
  code: string
  period: number
  remaining: number
}

/** What opens a vault: a password, a key file, or both. */
export interface VaultKeyInput {
  password: string | null
  /** The password given as its SHA-256, as the account keeps it; opens and saves as the password does. */
  passwordHash?: Uint8Array | null
  keyFile: Uint8Array | null
}

/** The standard fields, in KeePass's order. */
export const STANDARD_FIELDS = ['Title', 'UserName', 'Password', 'URL', 'Notes'] as const

export function fieldValue(entry: Pick<EntryView, 'fields'>, key: string): string {
  return entry.fields.find((f) => f.key === key)?.value ?? ''
}
