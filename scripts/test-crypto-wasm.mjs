import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const modulePath = new URL(
  '../frontend/public/crypto-wasm/kutup_crypto_wasm.js',
  import.meta.url,
)
const wasmPath = `${root}/frontend/public/crypto-wasm/kutup_crypto_wasm_bg.wasm`
const crypto = await import(modulePath)
const wasm = await readFile(wasmPath)
await crypto.default({ module_or_path: wasm })

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

const driveFileBlob = crypto.prepareDriveFileBlob(
  Buffer.alloc(32, 0x42).toString('base64'),
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  7,
)
assert.deepEqual(driveFileBlob, {
  objectHeader: 'S1VUUERCMQAAAQEAAAAABxEREREREUERgREREREREREiIiIiIiJCIoIiIiIiIiIi',
  streamKey: 'oh2pAz4XSGfBLgZy6N0Nrhys73xJjj+eh4RTpAqjttg=',
})
assert.equal(
  crypto.openDriveFileBlobHeader(
    driveFileBlob.objectHeader,
    Buffer.alloc(32, 0x42).toString('base64'),
    '11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222',
    7,
  ),
  driveFileBlob.streamKey,
)
assert.throws(
  () => crypto.openDriveFileBlobHeader(
    driveFileBlob.objectHeader,
    Buffer.alloc(32, 0x42).toString('base64'),
    '33333333-3333-4333-8333-333333333333',
    '22222222-2222-4222-8222-222222222222',
    7,
  ),
  /context does not match/,
)

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

console.log('crypto WASM canonical vectors passed')
