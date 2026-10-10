import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const modulePath = new URL(
  '../frontend/wasm/crypto-wasm/kutup_crypto_wasm.js',
  import.meta.url,
)
const wasmPath = `${root}/frontend/wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm`
const crypto = await import(modulePath)
const wasm = await readFile(wasmPath)
await crypto.default({ module_or_path: wasm })
const vectors = JSON.parse(
  await readFile(`${root}/crates/kutup-crypto/tests/vectors/crypto.json`, 'utf8'),
)

const keys = crypto.deriveAccountProtectionKeys(
  'correct horse battery staple',
  'MDEyMzQ1Njc4OWFiY2RlZg==',
  1,
  65_536,
  3,
  1,
)
assert.deepEqual(keys, {
  keyEncryptionKey: 'dgUIbPObROQzY5NoEVSeiNn1cmCX+T5aHgdIUVuNrG0=',
  loginKey: 'TqqiEotO6otWBWRjUcGqYnDkmonT51Smn/AfBCJLf/4=',
})

const entropy = Buffer.from(Uint8Array.from({ length: 32 }, (_, index) => index)).toString('base64')
assert.equal(
  crypto.deriveRecoveryAuthProof(entropy, ' Alice@Example.COM '),
  'WCApZxc1kEKYdt6Ygph4RpjnSq23mfVOuZRu/YdM6sQ=',
)
assert.throws(
  () => crypto.deriveAccountProtectionKeys('password', 'MDEyMzQ1Njc4OWFiY2RlZg==', 1, 32_768, 3, 1),
  /parameters/,
)
assert.throws(
  () => crypto.deriveRecoveryAuthProof('AA==', 'alice@example.com'),
  /32 bytes/,
)

assert.deepEqual(
  crypto.deriveAccountIdentityKeys('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='),
  {
    authorityPublicKey: 'eYfen0GgcbJ7PEdEgpsPFRSB9Mi55ZfV+O7e6/P1Kfw=',
    authorityKeyId: '19c53cf8e1cf6790e78bd859ad391db080cc5b3fec885eb345e76b664ce694d3',
    incarnationId: '3a6ef6bc771054da75a5c5dd018bcfdbc1ed1fcc5126af4248a005b7a95cf895',
    driveHpkePublicKey: 'XWVa5lRpqR/0hLnBSe3MoSY9Bj1LVUcHuSa7kylCpyY=',
    driveHpkePrivateKey: '9XjSilnTBqLghIX2V5ZpFVHHfv/hnBAX/MNvekiHD/A=',
    driveSigningPublicKey: 'q7EjHuex0qgzED93MUSVrAKqBU7mfJY48zjVt8xsp1c=',
  },
)

const envelopePlaintext = Buffer.alloc(32, 0x42).toString('base64')
const envelopeKey = Buffer.alloc(32, 0x24).toString('base64')
const accountEnvelope = crypto.sealAccountEnvelope(
  envelopePlaintext,
  envelopeKey,
  1,
  ' Alice@Example.COM ',
)
assert.equal(
  crypto.openAccountEnvelope(accountEnvelope, envelopeKey, 1, 'alice@example.com'),
  envelopePlaintext,
)
assert.throws(
  () => crypto.openAccountEnvelope(accountEnvelope, envelopeKey, 2, 'alice@example.com'),
  /authentication failed/,
)
assert.throws(
  () => crypto.openAccountEnvelope(accountEnvelope, envelopeKey, 1, 'mallory@example.com'),
  /authentication failed/,
)

const driveEnvelope = crypto.sealDriveEnvelope(
  Buffer.from('projects').toString('base64'),
  Buffer.alloc(32, 0x33).toString('base64'),
  2,
  7,
  11n,
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
)
assert.equal(
  crypto.openDriveEnvelope(
    driveEnvelope,
    Buffer.alloc(32, 0x33).toString('base64'),
    2,
    7,
    11n,
    '11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222',
  ),
  Buffer.from('projects').toString('base64'),
)
assert.throws(
  () => crypto.openDriveEnvelope(
    driveEnvelope,
    Buffer.alloc(32, 0x33).toString('base64'),
    2,
    7,
    12n,
    '11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222',
  ),
  /authentication failed/,
)

// A link to one file: purpose 11, epoch = the file key's generation.
{
  const fileKey = Buffer.alloc(32, 0x55).toString('base64')
  const linkKey = Buffer.alloc(32, 0x66).toString('base64')
  const file = '11111111-1111-4111-8111-111111111111'
  const owner = '22222222-2222-4222-8222-222222222222'
  const wrapped = crypto.sealDriveEnvelope(fileKey, linkKey, 11, 3, 1n, file, owner)
  assert.equal(crypto.openDriveEnvelope(wrapped, linkKey, 11, 3, 1n, file, owner), fileKey)
  assert.throws(() => crypto.openDriveEnvelope(wrapped, linkKey, 11, 4, 1n, file, owner), /authentication failed/)
  assert.throws(() => crypto.openDriveEnvelope(wrapped, linkKey, 5, 3, 1n, file, owner), /authentication failed/)
}

// A photo in an album: purpose 12, epoch = the album's epoch, revision = the generation.
{
  const fileKey = Buffer.alloc(32, 0x55).toString('base64')
  const albumKey = Buffer.alloc(32, 0x77).toString('base64')
  const file = '11111111-1111-4111-8111-111111111111'
  const album = '22222222-2222-4222-8222-222222222222'
  const wrapped = crypto.sealDriveEnvelope(fileKey, albumKey, 12, 2, 3n, file, album)
  assert.equal(crypto.openDriveEnvelope(wrapped, albumKey, 12, 2, 3n, file, album), fileKey)
  assert.throws(() => crypto.openDriveEnvelope(wrapped, albumKey, 12, 1, 3n, file, album), /authentication failed/)
  assert.throws(() => crypto.openDriveEnvelope(wrapped, albumKey, 3, 2, 3n, file, album), /authentication failed/)
}

// File blobs are bound to the file and the file key's generation, not a folder.
const blobVector = vectors.driveFileBlob
const driveFileBlob = crypto.prepareDriveFileBlob(blobVector.fileKey, blobVector.fileId, blobVector.generation)
assert.deepEqual(driveFileBlob, {
  objectHeader: blobVector.objectHeader,
  streamKey: blobVector.derivedStreamKey,
})
assert.equal(
  crypto.openDriveFileBlobHeader(
    driveFileBlob.objectHeader,
    blobVector.fileKey,
    blobVector.fileId,
    blobVector.generation,
  ),
  driveFileBlob.streamKey,
)
for (const [fileId, generation] of [
  ['33333333-3333-4333-8333-333333333333', blobVector.generation],
  [blobVector.fileId, blobVector.generation + 1],
]) {
  assert.throws(
    () => crypto.openDriveFileBlobHeader(driveFileBlob.objectHeader, blobVector.fileKey, fileId, generation),
    /context does not match/,
  )
}

const identityMaster = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
const collectionKey = Buffer.alloc(32, 0x33).toString('base64')
const epochStatement = crypto.createCollectionEpochStatement(
  identityMaster,
  collectionKey,
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  1,
  '',
)
assert.match(
  crypto.verifyCollectionEpochStatement(
    epochStatement,
    crypto.deriveAccountIdentityKeys(identityMaster).authorityPublicKey,
    collectionKey,
    '11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222',
    1,
    '',
  ),
  /^[0-9a-f]{64}$/,
)
assert.throws(
  () => crypto.verifyCollectionEpochStatement(
    epochStatement,
    crypto.deriveAccountIdentityKeys(identityMaster).authorityPublicKey,
    Buffer.alloc(32, 0x34).toString('base64'),
    '11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222',
    1,
    '',
  ),
  /authentication failed/,
)

const senderIdentity = crypto.deriveAccountIdentityKeys(
  Buffer.alloc(32, 1).toString('base64'),
)
const recipientIdentity = crypto.deriveAccountIdentityKeys(
  Buffer.alloc(32, 2).toString('base64'),
)
const namedShareEnvelope = crypto.sealNamedShareEnvelope(
  collectionKey,
  Buffer.alloc(32, 1).toString('base64'),
  recipientIdentity.driveHpkePublicKey,
  '11111111-1111-4111-8111-111111111111',
  3,
  'alice@a.test',
  senderIdentity.incarnationId,
  'bob@b.test',
  recipientIdentity.incarnationId,
)
assert.equal(
  crypto.openNamedShareEnvelope(
    namedShareEnvelope,
    senderIdentity.driveSigningPublicKey,
    recipientIdentity.driveHpkePrivateKey,
    '11111111-1111-4111-8111-111111111111',
    3,
    'alice@a.test',
    senderIdentity.incarnationId,
    'bob@b.test',
    recipientIdentity.incarnationId,
  ),
  collectionKey,
)
assert.throws(
  () => crypto.openNamedShareEnvelope(
    namedShareEnvelope,
    senderIdentity.driveSigningPublicKey,
    recipientIdentity.driveHpkePrivateKey,
    '11111111-1111-4111-8111-111111111111',
    4,
    'alice@a.test',
    senderIdentity.incarnationId,
    'bob@b.test',
    recipientIdentity.incarnationId,
  ),
  /authentication failed/,
)

const attachmentId = '11111111-1111-4111-8111-111111111111'
const attachmentKey = Buffer.alloc(32, 0x42).toString('base64')
const chatMedia = crypto.prepareChatMediaObject(attachmentKey, attachmentId)
assert.deepEqual(chatMedia, {
  objectHeader: 'S1VUUENNMQAAAQEAERERERERQRGBEREREREREQ==',
  streamKey: 'pV4kyXvsX6NrGxJmf9SVT3kNGZu2EgwWQWC/qS2kbF8=',
})
assert.equal(
  crypto.openChatMediaObjectHeader(chatMedia.objectHeader, attachmentKey, attachmentId),
  chatMedia.streamKey,
)
assert.throws(
  () => crypto.openChatMediaObjectHeader(
    chatMedia.objectHeader,
    attachmentKey,
    '22222222-2222-4222-8222-222222222222',
  ),
  /context does not match/,
)

const ledgerMaster = Buffer.alloc(32, 0x33).toString('base64')
const ledgerKey = crypto.deriveChatAttachmentLedgerKey(ledgerMaster)
assert.equal(ledgerKey, 'DMmsEZ6NNSfT7l124msOjoY/0UfO2sYFtMqQwZ3m2SU=')
const ledgerIncarnation = '11'.repeat(32)
const ledgerEntity = '22222222-2222-4222-8222-222222222222'
const ledgerPlaintext = Buffer.from('canonical ledger entry').toString('base64')
const ledgerEnvelope = crypto.sealChatAttachmentLedger(
  ledgerPlaintext,
  ledgerKey,
  ledgerIncarnation,
  ledgerEntity,
  1n,
  '',
)
assert.equal(
  crypto.openChatAttachmentLedger(
    ledgerEnvelope,
    ledgerKey,
    ledgerIncarnation,
    ledgerEntity,
    1n,
    '',
  ),
  ledgerPlaintext,
)
assert.match(crypto.chatAttachmentLedgerEnvelopeDigest(ledgerEnvelope), /^[0-9a-f]{64}$/)
assert.throws(
  () => crypto.openChatAttachmentLedger(
    ledgerEnvelope,
    ledgerKey,
    ledgerIncarnation,
    '33333333-3333-4333-8333-333333333333',
    1n,
    '',
  ),
  /authentication failed/,
)

const backupRoot = Buffer.alloc(32, 0x55).toString('base64')
const backupId = '44444444-4444-4444-8444-444444444444'
const backupAuthorization = crypto.createChatBackupSignerAuthorization(
  identityMaster,
  backupRoot,
  backupId,
  1_800_000_000n,
)
const verifiedAuthorization = crypto.verifyChatBackupMetadata(
  backupAuthorization,
  null,
  identityMaster,
  backupRoot,
  backupId,
)
assert.match(verifiedAuthorization.signerAuthorizationDigest, /^[0-9a-f]{64}$/)
assert.equal(verifiedAuthorization.manifestDigest, undefined)

const backupSegment = {
  version: 1,
  records: [{
    version: 1,
    recordId: '55555555-5555-4555-8555-555555555555',
    mutationSequence: 1,
    conversation: { kind: 'direct', address: { username: 'bob', server: 'b.test' } },
    sender: 'alice@a.test',
    senderDeviceId: 1,
    outgoing: true,
    content: {
      version: 1,
      kind: 'text',
      sentAt: '2026-08-11T12:00:00Z',
      seq: '1',
      body: { text: 'protected' },
      text: 'protected',
    },
    timestampMs: 1_800_000_000_000,
    delivered: true,
    tombstone: false,
  }],
}
const canonicalBackupSegment = crypto.encodeChatBackupPlaintext(backupSegment, 2)
assert.deepEqual(
  crypto.decodeChatBackupPlaintext(canonicalBackupSegment, 2),
  backupSegment,
)
const backupOperation = '66666666-6666-4666-8666-666666666666'
const sealedBackupSegment = crypto.sealChatBackupObject(
  canonicalBackupSegment,
  backupRoot,
  crypto.deriveAccountIdentityKeys(identityMaster).incarnationId,
  backupId,
  2,
  backupOperation,
  1,
  1n,
  '0'.repeat(64),
)
assert.equal(
  crypto.openChatBackupObject(
    sealedBackupSegment,
    backupRoot,
    crypto.deriveAccountIdentityKeys(identityMaster).incarnationId,
    backupId,
    2,
    backupOperation,
    1,
    1n,
    '0'.repeat(64),
  ),
  canonicalBackupSegment,
)
const backupManifest = crypto.signChatBackupManifest({
  version: 1,
  backupIncarnationId: backupId,
  suite: 1,
  protectionDomain: 1,
  generation: 1,
  previousManifestDigest: '0'.repeat(64),
  baseObjectId: '77777777-7777-4777-8777-777777777777',
  baseCiphertextBytes: 100,
  baseCiphertextSha256: '11'.repeat(32),
  coveredCursor: 1,
  mediaReferenceSetDigest: '22'.repeat(32),
  signerAuthorizationDigest: verifiedAuthorization.signerAuthorizationDigest,
  createdAtUnix: 1_800_000_001,
  signature: '',
}, backupRoot, crypto.deriveAccountIdentityKeys(identityMaster).incarnationId, backupId)
assert.match(
  crypto.verifyChatBackupMetadata(
    backupAuthorization,
    backupManifest,
    identityMaster,
    backupRoot,
    backupId,
  ).manifestDigest,
  /^[0-9a-f]{64}$/,
)
const backupMedia = crypto.prepareChatBackupMedia(
  backupRoot,
  crypto.deriveAccountIdentityKeys(identityMaster).incarnationId,
  backupId,
  attachmentId,
  10_000n,
)
assert.match(backupMedia.mediaId, /^[0-9a-f]{64}$/)
assert.equal(backupMedia.paddedPlaintextBytes >= 10_000, true)
assert.equal(Buffer.from(backupMedia.objectHeader, 'base64').length, 107)

// Local-state envelopes: session-fork payloads (2) and persisted web
// sessions (3) open to the canonical Rust vectors, fail closed on the wrong
// purpose or profile, and the CLI-only purpose is refused.
const localState = vectors.localState
for (const [vector, purpose] of [
  [localState.sessionFork, 2],
  [localState.webSession, 3],
]) {
  assert.equal(
    crypto.openLocalState(vector.envelope, localState.key, purpose, vector.profile),
    vector.plaintext,
  )
  const resealed = crypto.sealLocalState(vector.plaintext, localState.key, purpose, vector.profile)
  assert.notEqual(resealed, vector.envelope, 'nonce must be random')
  assert.equal(
    crypto.openLocalState(resealed, localState.key, purpose, vector.profile),
    vector.plaintext,
  )
}
assert.throws(() =>
  crypto.openLocalState(localState.sessionFork.envelope, localState.key, 2, 'web-chat'),
)
assert.throws(() =>
  crypto.openLocalState(localState.sessionFork.envelope, localState.key, 3, 'web-drive'),
)
assert.throws(
  () => crypto.sealLocalState(localState.sessionFork.plaintext, localState.key, 1, 'default'),
  /not available to web clients/,
)

// Thumbnails: the canonical envelope opens to the vector's picture, only as
// its own variant, file and key generation; a fresh seal round-trips; the
// generic envelope export refuses the purposes that have typed exports.
const thumb = vectors.thumbnail
assert.deepEqual(
  crypto.openThumbnail(thumb.envelope, thumb.variant, thumb.fileKey, thumb.fileId, thumb.generation),
  { format: 1, width: thumb.width, height: thumb.height, image: thumb.image },
)
assert.throws(() => crypto.openThumbnail(thumb.envelope, 'lg', thumb.fileKey, thumb.fileId, thumb.generation))
assert.throws(() =>
  crypto.openThumbnail(thumb.envelope, thumb.variant, thumb.fileKey, '33333333-3333-4333-8333-333333333333', thumb.generation),
)
const resealedThumb = crypto.sealThumbnail(
  thumb.image, 1, thumb.width, thumb.height, thumb.variant, thumb.fileKey, thumb.fileId, thumb.generation,
)
assert.notEqual(resealedThumb, thumb.envelope, 'nonce must be random')
assert.equal(
  crypto.openThumbnail(resealedThumb, thumb.variant, thumb.fileKey, thumb.fileId, thumb.generation).image,
  thumb.image,
)
assert.throws(
  () => crypto.sealThumbnail(Buffer.from('<svg/>').toString('base64'), 3, 10, 10, 'sm', thumb.fileKey, thumb.fileId, 1),
  /format/,
)
for (const purpose of [6, 7, 8, 10]) {
  assert.throws(
    () => crypto.sealDriveEnvelope(thumb.image, thumb.fileKey, purpose, 1, 1n, thumb.fileId, thumb.fileId),
    /typed export/,
  )
}

// A rotated folder's keyring: the current key unlocks every older one
// through the signed chain; an older key (a removed member's) does not.
const ring = vectors.collectionKeyring
const ringChain = ring.chain.map((link) => ({
  epoch: link.epoch,
  epochStatement: link.statement,
  previousKeyEnvelope: link.previousKeyEnvelope ?? undefined,
}))
assert.deepEqual(
  crypto.unlockCollectionKeyring(ring.keys.at(-1), ring.collectionId, ring.ownerUserId, ring.authorityPublicKey, ringChain),
  ring.keys,
)
assert.throws(() =>
  crypto.unlockCollectionKeyring(ring.keys[1], ring.collectionId, ring.ownerUserId, ring.authorityPublicKey, ringChain),
)
assert.throws(() =>
  crypto.unlockCollectionKeyring(ring.keys.at(-1), ring.collectionId, ring.ownerUserId, ring.authorityPublicKey, [
    ringChain[0],
    ringChain[2],
  ]),
)
const resealedPrevious = crypto.sealPreviousCollectionKey(ring.keys[1], ring.keys[2], ring.collectionId, ring.ownerUserId, 3)
assert.deepEqual(
  crypto.unlockCollectionKeyring(ring.keys.at(-1), ring.collectionId, ring.ownerUserId, ring.authorityPublicKey, [
    ringChain[0],
    ringChain[1],
    { ...ringChain[2], previousKeyEnvelope: resealedPrevious },
  ]),
  ring.keys,
)

// A file's key chain: the current key reaches every older generation; an
// older key (a removed member's) opens nothing newer.
const fileRing = vectors.fileKeyring
const fileGeneration = fileRing.keys.length
fileRing.keys.forEach((key, index) => {
  assert.equal(
    crypto.fileKeyAt(fileRing.keys.at(-1), fileRing.fileId, fileGeneration, fileRing.chain, index + 1),
    key,
  )
})
assert.throws(() => crypto.fileKeyAt(fileRing.keys[1], fileRing.fileId, fileGeneration, fileRing.chain, 1))
assert.throws(() => crypto.fileKeyAt(fileRing.keys.at(-1), fileRing.fileId, fileGeneration, fileRing.chain.slice(1), 2))
const resealedFileKey = crypto.sealPreviousFileKey(fileRing.keys[1], fileRing.keys[2], fileRing.fileId, 3)
assert.equal(
  crypto.fileKeyAt(fileRing.keys.at(-1), fileRing.fileId, fileGeneration, [
    fileRing.chain[0],
    { ...fileRing.chain[1], previousKeyEnvelope: resealedFileKey },
  ], 1),
  fileRing.keys[0],
)

// A single-file share opens only as a file share, for its file and generation.
{
  const owner = crypto.deriveAccountIdentityKeys(Buffer.alloc(32, 1).toString('base64'))
  const reader = crypto.deriveAccountIdentityKeys(Buffer.alloc(32, 2).toString('base64'))
  const fileId = '22222222-2222-4222-8222-222222222222'
  const sealed = crypto.sealFileShareEnvelope(
    Buffer.alloc(32, 0x66).toString('base64'), Buffer.alloc(32, 1).toString('base64'), reader.driveHpkePublicKey,
    fileId, 2, 'alice@a.test', owner.incarnationId, 'bob@a.test', reader.incarnationId,
  )
  const open = (file, generation) => crypto.openFileShareEnvelope(
    sealed, owner.driveSigningPublicKey, reader.driveHpkePrivateKey,
    file, generation, 'alice@a.test', owner.incarnationId, 'bob@a.test', reader.incarnationId,
  )
  assert.equal(open(fileId, 2), Buffer.alloc(32, 0x66).toString('base64'))
  assert.throws(() => open(fileId, 3))
  assert.throws(() => crypto.openNamedShareEnvelope(
    sealed, owner.driveSigningPublicKey, reader.driveHpkePrivateKey,
    fileId, 2, 'alice@a.test', owner.incarnationId, 'bob@a.test', reader.incarnationId,
  ))
}

// A live-location update: the canonical bytes open, a fresh seal round-trips,
// and another stream's id or a tampered byte opens nothing.
const live = vectors.liveLocation
assert.deepEqual(crypto.liveLocationOpen(live.key, live.streamId, live.envelope), { counter: live.counter, ...live.point })
const liveSealed = crypto.liveLocationSeal(live.key, live.streamId, 8, 40.99, 29.02, 5, 1790000000123)
assert.deepEqual(crypto.liveLocationOpen(live.key, live.streamId, liveSealed), { counter: 8, lat: 40.99, lon: 29.02, accuracyM: 5, atMs: 1790000000123 })
assert.throws(() => crypto.liveLocationOpen(live.key, '00'.repeat(16), live.envelope))
assert.throws(() => crypto.liveLocationSeal(live.key, live.streamId, 0, 1, 1, 1, 1))

// Whiteboard assets and collaboration frames sit under the file key.
const assetVector = vectors.asset
assert.equal(
  crypto.openWhiteboardAsset(assetVector.envelope, assetVector.fileKey, assetVector.fileId, assetVector.assetId, assetVector.generation),
  assetVector.plaintext,
)
assert.throws(() =>
  crypto.openWhiteboardAsset(assetVector.envelope, assetVector.fileKey, assetVector.fileId, assetVector.assetId, assetVector.generation + 1),
)
const frameVector = vectors.collabFrame
const openedFrame = crypto.openCollabFrame(frameVector.frame, frameVector.fileKey, frameVector.fileId, frameVector.keyGeneration)
assert.equal(openedFrame.plaintext, frameVector.plaintext)
assert.equal(openedFrame.keyGeneration, frameVector.keyGeneration)
assert.equal(crypto.collabFrameKeyGeneration(frameVector.frame), frameVector.keyGeneration)
assert.throws(() =>
  crypto.openCollabFrame(frameVector.frame, frameVector.fileKey, frameVector.fileId, frameVector.keyGeneration + 1),
)

const metadataVector = vectors.fileMetadata
for (const { input, output } of metadataVector.canonical) {
  assert.equal(crypto.canonicalFileMetadata(input), output)
  assert.equal(crypto.canonicalFileMetadata(output), output)
}
for (const bad of metadataVector.invalid) {
  assert.throws(() => crypto.canonicalFileMetadata(bad))
}
const contentHasher = new crypto.ContentHasher()
for (const chunk of metadataVector.contentHash.chunks) contentHasher.update(Buffer.from(chunk, 'base64'))
assert.equal(contentHasher.finish(), metadataVector.contentHash.hash)
assert.throws(() => contentHasher.finish())

const libraryVector = vectors.photosLibrary
assert.equal(crypto.photosLibraryKey(libraryVector.masterKey), libraryVector.libraryKey)
const firstLibrary = crypto.openPhotosLibrary(libraryVector.first.envelope, libraryVector.libraryKey, libraryVector.accountIncarnationId, 1, undefined)
assert.equal(firstLibrary, libraryVector.first.plaintext)
assert.equal(crypto.photosLibraryDigest(libraryVector.first.envelope), libraryVector.first.digest)
assert.equal(
  crypto.openPhotosLibrary(libraryVector.second.envelope, libraryVector.libraryKey, libraryVector.accountIncarnationId, 2, libraryVector.first.digest),
  libraryVector.second.plaintext,
)
assert.throws(() => crypto.openPhotosLibrary(libraryVector.second.envelope, libraryVector.libraryKey, libraryVector.accountIncarnationId, 1, undefined))
const resealed = crypto.sealPhotosLibrary(
  JSON.stringify({ favourites: ['33333333-3333-4333-8333-333333333333', '22222222-2222-4222-8222-222222222222'], archived: [], hidden: [] }),
  libraryVector.libraryKey, libraryVector.accountIncarnationId, 3, crypto.photosLibraryDigest(libraryVector.second.envelope),
)
assert.equal(crypto.photosLibraryDigest(resealed.envelope), resealed.digest)
assert.equal(
  crypto.openPhotosLibrary(resealed.envelope, libraryVector.libraryKey, libraryVector.accountIncarnationId, 3, crypto.photosLibraryDigest(libraryVector.second.envelope)),
  '{"favourites":["22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333"],"archived":[],"hidden":[]}',
)

// Mail address keys (docs/plans/mail-address-keys.md).
const mailVectors = JSON.parse(
  await readFile(`${root}/crates/kutup-crypto/tests/vectors/mail-address-key-v1.json`, 'utf8'),
)
const mailIdentity = crypto.deriveAccountIdentityKeys(mailVectors.masterKey)
assert.deepEqual(crypto.inspectMailAddressPublicKey(mailVectors.publicKey, mailVectors.address), {
  fingerprint: mailVectors.fingerprint,
  sha256Fingerprint: mailVectors.sha256Fingerprint,
  createdAt: mailVectors.createdAt,
})
assert.throws(() => crypto.inspectMailAddressPublicKey(mailVectors.publicKey, 'bob@kutup.dev'))
assert.match(crypto.armorMailPublicKey(mailVectors.publicKey), /^-----BEGIN PGP PUBLIC KEY BLOCK-----/)
const [firstList, secondList] = mailVectors.keyLists
const verifiedFirst = crypto.verifyMailKeyList(firstList.data, firstList.signature, mailIdentity.authorityPublicKey)
assert.equal(verifiedFirst.hash, firstList.hash)
assert.equal(verifiedFirst.sequence, 1)
const verifiedSecond = crypto.verifyMailKeyList(
  secondList.data, secondList.signature, mailIdentity.authorityPublicKey, firstList.data, firstList.signature,
)
assert.equal(verifiedSecond.hash, secondList.hash)
assert.equal(verifiedSecond.keys.filter((key) => key.primary).length, 1)
assert.throws(() => crypto.verifyMailKeyList(firstList.data, firstList.signature, mailIdentity.authorityPublicKey, secondList.data, secondList.signature))
const otherIdentity = crypto.deriveAccountIdentityKeys(Buffer.alloc(32, 0x07).toString('base64'))
assert.throws(() => crypto.verifyMailKeyList(firstList.data, firstList.signature, otherIdentity.authorityPublicKey))
// The same list signed again from the browser is byte-identical.
const resigned = crypto.signMailKeyList(mailVectors.masterKey, {
  account: verifiedFirst.account,
  address: verifiedFirst.address,
  sequence: 1,
  issuedAt: verifiedFirst.issuedAt,
  keys: verifiedFirst.keys,
})
assert.equal(resigned.data, firstList.data)
assert.equal(resigned.signature, firstList.signature)
// A fresh key: sealed in WASM, never returned in clear.
const fresh = crypto.generateMailAddressKey(mailVectors.masterKey, mailVectors.loginEmail, 'carol@kutup.dev', 1_790_000_000)
assert.deepEqual(Object.keys(fresh).sort(), ['envelope', 'fingerprint', 'publicKey', 'sha256Fingerprint'])
assert.equal(crypto.inspectMailAddressPublicKey(fresh.publicKey, 'carol@kutup.dev').fingerprint, fresh.fingerprint)
// The generic account-envelope path refuses the mail-key purpose.
assert.throws(() => crypto.openAccountEnvelope(fresh.envelope, mailVectors.masterKey, 5, mailVectors.loginEmail), /typed export/)
assert.throws(() => crypto.sealAccountEnvelope('AA==', mailVectors.masterKey, 5, mailVectors.loginEmail), /typed export/)

// Mail between Kutup users (docs/plans/mail.md): a split message opens for
// each recipient with the shared data packet; fresh ones round-trip.
const splitVectors = JSON.parse(
  await readFile(`${root}/crates/kutup-crypto/tests/vectors/mail-split-v1.json`, 'utf8'),
)
const arrivalVectors = JSON.parse(
  await readFile(`${root}/crates/kutup-crypto/tests/vectors/mail-arrival-v1.json`, 'utf8'),
)
const b64bytes = (value) => new Uint8Array(Buffer.from(value, 'base64'))
const joinPackets = (key, data) => new Uint8Array([...b64bytes(key), ...data])
const aliceEnvelope = mailVectors.envelope
const openAs = (message, sender) =>
  crypto.openMailMessage(mailVectors.masterKey, mailVectors.loginEmail, mailVectors.address, aliceEnvelope, mailVectors.fingerprint, message, sender)
const splitData = b64bytes(splitVectors.dataPacket)
const alicesCopy = openAs(joinPackets(splitVectors.keyPackets[0], splitData), mailVectors.publicKey)
assert.deepEqual(Buffer.from(alicesCopy.data), Buffer.from(splitVectors.plaintext, 'base64'))
assert.equal(alicesCopy.signed, true)
assert.equal(alicesCopy.verified, true)
assert.throws(() => openAs(joinPackets(splitVectors.keyPackets[1], splitData), mailVectors.publicKey))
const arrived = openAs(b64bytes(arrivalVectors.ciphertext), undefined)
assert.deepEqual(Buffer.from(arrived.data), Buffer.from(arrivalVectors.plaintext, 'base64'))
assert.equal(arrived.signed, false)
assert.equal(arrived.verified, false)
assert.throws(() =>
  crypto.openMailMessage(mailVectors.masterKey, mailVectors.loginEmail, 'bob@kutup.dev', aliceEnvelope, mailVectors.fingerprint, b64bytes(arrivalVectors.ciphertext)),
)
const sealedMail = crypto.encryptMailMessage(
  mailVectors.masterKey, mailVectors.loginEmail, mailVectors.address, aliceEnvelope, mailVectors.fingerprint,
  [mailVectors.publicKey, splitVectors.bobPublicKey], new TextEncoder().encode('hello bob'),
)
assert.equal(sealedMail.keyPackets.length, 2)
const reopenedMail = openAs(joinPackets(sealedMail.keyPackets[0], sealedMail.dataPacket), mailVectors.publicKey)
assert.equal(new TextDecoder().decode(reopenedMail.data), 'hello bob')
assert.equal(reopenedMail.verified, true)

// Contacts (docs/plans/contacts.md).
const contactVectors = JSON.parse(
  await readFile(`${root}/crates/kutup-crypto/tests/vectors/contact-card-v1.json`, 'utf8'),
)
const contactIdentity = crypto.deriveAccountIdentityKeys(contactVectors.masterKey)
// Signing a reordered summary gives the canonical bytes and the vector signature.
const reordered = JSON.parse(contactVectors.summary)
const shuffled = JSON.stringify({ pinnedKeys: reordered.pinnedKeys, groups: reordered.groups, emails: reordered.emails, name: reordered.name, uid: reordered.uid })
const signedContact = crypto.signContactSummary(contactVectors.masterKey, contactVectors.account, shuffled)
assert.equal(signedContact.summary, contactVectors.summary)
assert.equal(signedContact.signature, contactVectors.signature)
assert.equal(
  crypto.verifyContactSummary(contactVectors.summary, contactVectors.signature, contactVectors.account, contactIdentity.authorityPublicKey).name,
  'Ayşe Yılmaz',
)
assert.throws(() => crypto.verifyContactSummary(contactVectors.summary.replace('ayse@example.com', 'evil@example.com'), contactVectors.signature, contactVectors.account, contactIdentity.authorityPublicKey))
assert.throws(() => crypto.verifyContactSummary(contactVectors.summary, contactVectors.signature, 'bob@kutup.dev', contactIdentity.authorityPublicKey))
assert.equal(
  crypto.openContactCard(contactVectors.masterKey, contactVectors.account, contactVectors.uid, contactVectors.sealed),
  contactVectors.vcard,
)
const resealedCard = crypto.sealContactCard(contactVectors.masterKey, contactVectors.account, contactVectors.uid, contactVectors.vcard)
assert.equal(crypto.openContactCard(contactVectors.masterKey, contactVectors.account, contactVectors.uid, resealedCard), contactVectors.vcard)
assert.throws(() => crypto.openContactCard(contactVectors.masterKey, contactVectors.account, 'another-uid', resealedCard))

console.log('crypto WASM canonical vectors passed')
