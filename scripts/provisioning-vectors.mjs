// Independent implementation of the provisioning cipher (Signal Desktop's
// mock-server `encryptProvisionMessage`, in node:crypto) that writes
// crates/kutup-crypto/tests/vectors/provisioning-v1.json. The Rust cipher must
// reproduce every case byte for byte and open it; the `signal` cases use
// Signal's own info string, so they check the construction is Signal's.
// Usage: node scripts/provisioning-vectors.mjs > crates/kutup-crypto/tests/vectors/provisioning-v1.json
import crypto from 'node:crypto';

const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');

function privateKey(raw) {
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_X25519, raw]),
    format: 'der',
    type: 'pkcs8',
  });
}

// libsignal's serialized public key: 0x05 ‖ X25519.
function publicKey(raw) {
  const jwk = crypto.createPublicKey(privateKey(raw)).export({ format: 'jwk' });
  return Buffer.concat([Buffer.from([5]), Buffer.from(jwk.x, 'base64url')]);
}

function seal(info, ephemeral, iv, recipientPublic, message) {
  const peer = crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: recipientPublic.subarray(1).toString('base64url') },
    format: 'jwk',
  });
  const agreement = crypto.diffieHellman({ privateKey: privateKey(ephemeral), publicKey: peer });
  const secrets = Buffer.from(crypto.hkdfSync('sha256', agreement, Buffer.alloc(32), info, 64));
  const cipher = crypto.createCipheriv('aes-256-cbc', secrets.subarray(0, 32), iv);
  const ciphertext = Buffer.concat([Buffer.from([1]), iv, cipher.update(message), cipher.final()]);
  const mac = crypto.createHmac('sha256', secrets.subarray(32)).update(ciphertext).digest();
  return { senderPublic: publicKey(ephemeral), body: Buffer.concat([ciphertext, mac]) };
}

const fill = (byte, len) => Buffer.alloc(len, byte);
const cases = [
  ['kutup', 'Kutup Provisioning Message v1', 0x11, 0x22, 0x33, Buffer.alloc(0)],
  ['kutup', 'Kutup Provisioning Message v1', 0x44, 0x55, 0x66, Buffer.from('{"provisioningVersion":1}')],
  ['kutup', 'Kutup Provisioning Message v1', 0x77, 0x88, 0x99, Buffer.from(Array.from({ length: 300 }, (_, i) => i & 0xff))],
  ['signal', 'TextSecure Provisioning Message', 0x11, 0x22, 0x33, Buffer.from('a Signal ProvisionMessage')],
].map(([kind, info, recipient, ephemeral, iv, message]) => {
  const recipientPrivate = fill(recipient, 32);
  const sealed = seal(Buffer.from(info), fill(ephemeral, 32), fill(iv, 16), publicKey(recipientPrivate), message);
  return {
    kind,
    info,
    recipientPrivate: recipientPrivate.toString('base64'),
    recipientPublic: publicKey(recipientPrivate).toString('base64'),
    ephemeralPrivate: fill(ephemeral, 32).toString('base64'),
    iv: fill(iv, 16).toString('base64'),
    message: message.toString('base64'),
    senderPublic: sealed.senderPublic.toString('base64'),
    body: sealed.body.toString('base64'),
  };
});

process.stdout.write(JSON.stringify({ cases }, null, 2) + '\n');
