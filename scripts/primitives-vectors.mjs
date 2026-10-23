// Known answers for suite V1 of kutup_crypto::primitives
// (docs/plans/crypto-primitives.md), written by implementations other than
// the Rust ones: node:crypto (OpenSSL) for SHA-256, HMAC-SHA256, HKDF-SHA256
// and Ed25519, and libsodium (its own C, as WASM) for XChaCha20-Poly1305 and
// Argon2id. The Rust primitives must reproduce every case byte for byte.
// Fixed inputs only: rerunning writes the same file.
// Usage (from the repository root, after `pnpm -C frontend install`):
//   node scripts/primitives-vectors.mjs > crates/kutup-crypto/tests/vectors/primitives-v1.json
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../frontend/packages/crypto/package.json', import.meta.url));
const sodium = require('libsodium-wrappers-sumo');
await sodium.ready;

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const bytes = (text) => Buffer.from(text, 'utf8');
/** `n` bytes counting up from `start`, as the RFCs' examples are. */
const run = (start, n) => Buffer.from(Array.from({ length: n }, (_, i) => (start + i) & 0xff));

const hash = [bytes(''), bytes('abc'), run(0, 1000)].map((data) => ({
  data: hex(data),
  digest: crypto.createHash('sha256').update(data).digest('hex'),
}));

const mac = [
  // RFC 4231, cases 1 and 2.
  { key: Buffer.alloc(20, 0x0b), data: bytes('Hi There') },
  { key: bytes('Jefe'), data: bytes('what do ya want for nothing?') },
  { key: run(0, 32), data: bytes('kutup/primitives/mac/v1\0') },
].map(({ key, data }) => ({ key: hex(key), data: hex(data), tag: crypto.createHmac('sha256', key).update(data).digest('hex') }));

const kdf = [
  // RFC 5869, case 1, and an empty salt.
  { ikm: Buffer.alloc(22, 0x0b), salt: run(0, 13), info: run(0xf0, 10), length: 42 },
  { ikm: run(0, 32), salt: Buffer.alloc(0), info: bytes('kutup/primitives/kdf/v1\0'), length: 64 },
].map(({ ikm, salt, info, length }) => ({
  ikm: hex(ikm),
  salt: hex(salt),
  info: hex(info),
  okm: hex(crypto.hkdfSync('sha256', ikm, salt, info, length)),
}));

const aead = [
  // draft-irtf-cfrg-xchacha-03, A.3.1, and an empty plaintext.
  {
    key: run(0x80, 32),
    nonce: run(0x40, 24),
    aad: Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex'),
    plaintext: bytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
  },
  { key: run(1, 32), nonce: run(2, 24), aad: bytes('kutup/primitives/aead/v1\0'), plaintext: Buffer.alloc(0) },
].map(({ key, nonce, aad, plaintext }) => ({
  key: hex(key),
  nonce: hex(nonce),
  aad: hex(aad),
  plaintext: hex(plaintext),
  ciphertext: hex(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key)),
}));

const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const signature = [
  // RFC 8032, test 1 (empty message) and test 2.
  { seed: Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex'), message: Buffer.alloc(0) },
  { seed: Buffer.from('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', 'hex'), message: Buffer.from('72', 'hex') },
].map(({ seed, message }) => {
  const key = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: 'der', type: 'pkcs8' });
  const publicKey = Buffer.from(crypto.createPublicKey(key).export({ format: 'jwk' }).x, 'base64url');
  return { seed: hex(seed), publicKey: hex(publicKey), message: hex(message), signature: hex(crypto.sign(null, message, key)) };
});

// libsodium's crypto_pwhash: Argon2id v1.3, one lane. Small limits keep the
// test fast; the account's own (3, 64 MiB) are persisted parameters.
const pwhash = [{ password: bytes('correct horse battery staple'), salt: run(0x10, 16), ops: 2, mem: 8 * 1024 * 1024, length: 32 }].map(
  ({ password, salt, ops, mem, length }) => ({
    password: hex(password),
    salt: hex(salt),
    ops,
    mem,
    output: hex(sodium.crypto_pwhash(length, password, salt, ops, mem, sodium.crypto_pwhash_ALG_ARGON2ID13)),
  }),
);

process.stdout.write(`${JSON.stringify({ suite: 'V1', hash, mac, kdf, aead, signature, pwhash }, null, 2)}\n`);
