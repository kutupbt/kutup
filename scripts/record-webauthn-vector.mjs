#!/usr/bin/env node
// Records a WebAuthn vector (docs/plans/security-keys.md, D1): a key's real
// registration and sign-in answers, which tests/webauthn_vectors.rs checks
// again with the server's adapter.
//
//   node scripts/record-webauthn-vector.mjs chromium [--uv]   Chromium's virtual
//       authenticator (CTAP2, USB), through Playwright; no hardware.
//   node scripts/record-webauthn-vector.mjs device <name> [--uv]   a real key
//       (a YubiKey): a visible Chromium asks for a touch (and the PIN with --uv).
//
// Run from the repository root with tests/e2e's dependencies installed
// (`npm ci --prefix tests/e2e`). The vector lands in
// crates/kutup-crypto/tests/vectors/webauthn/<name>.json.
import { createRequire } from 'node:module'
import { randomBytes } from 'node:crypto'
import { writeFile } from 'node:fs/promises'

const require = createRequire(new URL('../tests/e2e/package.json', import.meta.url))
const { chromium } = require('@playwright/test')

const [kind, ...rest] = process.argv.slice(2)
const uv = rest.includes('--uv')
const deviceName = kind === 'device' ? rest.find((arg) => !arg.startsWith('--')) : undefined
if (!['chromium', 'device'].includes(kind) || (kind === 'device' && !deviceName)) {
  console.error('usage: record-webauthn-vector.mjs chromium [--uv] | device <name> [--uv]')
  process.exit(2)
}
const name = kind === 'chromium' ? `chromium-ctap2-es256${uv ? '-uv' : ''}` : `${deviceName}${uv ? '-uv' : ''}`

const rpId = 'kutup.test'
const origin = 'https://account.kutup.test'
const b64 = (bytes) => Buffer.from(bytes).toString('base64url')
const account = randomBytes(16)
const registrationChallenge = randomBytes(16)
const authenticationChallenge = randomBytes(16)
const userVerification = uv ? 'required' : 'discouraged'

const browser = await chromium.launch({ headless: kind === 'chromium' })
const context = await browser.newContext({ ignoreHTTPSErrors: true })
const page = await context.newPage()
await page.route(`${origin}/**`, (route) =>
  route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>Record a WebAuthn vector</title><p>Touch your key when it blinks.</p>' }),
)
await page.goto(`${origin}/`)
if (kind === 'chromium') {
  const cdp = await context.newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: false,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  })
}

const registration = await page.evaluate(
  async ({ rpId, account, challenge, userVerification }) => {
    const options = PublicKeyCredential.parseCreationOptionsFromJSON({
      rp: { id: rpId, name: 'Kutup' },
      user: { id: account, name: 'vector', displayName: 'vector' },
      challenge,
      pubKeyCredParams: [-8, -7, -35, -257].map((alg) => ({ type: 'public-key', alg })),
      timeout: 120000,
      attestation: 'none',
      authenticatorSelection: { residentKey: 'discouraged', requireResidentKey: false, userVerification },
    })
    return (await navigator.credentials.create({ publicKey: options })).toJSON()
  },
  { rpId, account: b64(account), challenge: b64(registrationChallenge), userVerification },
)
const authentication = await page.evaluate(
  async ({ rpId, challenge, id, transports, userVerification }) => {
    const options = PublicKeyCredential.parseRequestOptionsFromJSON({
      rpId,
      challenge,
      timeout: 120000,
      allowCredentials: [{ type: 'public-key', id, transports }],
      userVerification,
    })
    return (await navigator.credentials.get({ publicKey: options })).toJSON()
  },
  {
    rpId,
    challenge: b64(authenticationChallenge),
    id: registration.rawId,
    transports: registration.response.transports ?? [],
    userVerification,
  },
)
await browser.close()

const vector = {
  name,
  source: kind === 'chromium' ? 'Chromium virtual authenticator (CTAP2, USB), recorded with Playwright' : `a real security key: ${deviceName}`,
  rpId,
  origin,
  account: b64(account),
  registration: { challenge: b64(registrationChallenge), requireUv: uv, response: registration },
  authentication: { challenge: b64(authenticationChallenge), requireUv: uv, response: authentication },
}
const path = new URL(`../crates/kutup-crypto/tests/vectors/webauthn/${name}.json`, import.meta.url)
await writeFile(path, `${JSON.stringify(vector, null, 2)}\n`)
console.log(`wrote ${path.pathname}`)
