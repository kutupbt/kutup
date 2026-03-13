import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAppDispatch } from '../store'
import { setAuth } from '../store/authSlice'
import api from '../api/client'
import { decryptMasterKey, decryptPrivateKey, toBase64, fromBase64 } from '../crypto'

type Step = 'credentials' | 'deriving' | 'totp' | 'decrypting'

export default function Login() {
  const navigate = useNavigate()
  const dispatch = useAppDispatch()
  const [step, setStep] = useState<Step>('credentials')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [preAuthToken, setPreAuthToken] = useState('')
  const [error, setError] = useState('')

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setStep('deriving')

    try {
      // 1. Fetch KDF salts
      const preflightRes = await api.get(`/auth/login/preflight?email=${encodeURIComponent(email)}`)
      const { kdfSalt, loginKeySalt } = preflightRes.data

      let loginKeyB64: string
      let keyEncryptionKey: Uint8Array | null = null

      if (kdfSalt === '') {
        // Setup-mode account: no KDF, send raw password bytes as loginKey
        loginKeyB64 = toBase64(new TextEncoder().encode(password))
      } else {
        // Normal: derive keys via Argon2id
        const derived = await deriveInWorker(password, kdfSalt, loginKeySalt)
        keyEncryptionKey = derived.keyEncryptionKey
        loginKeyB64 = toBase64(derived.loginKey)
      }

      // 2. Login — send loginKey, server checks bcrypt
      const loginRes = await api.post('/auth/login', { email, loginKey: loginKeyB64 })

      if (loginRes.data.requiresSetup) {
        sessionStorage.setItem('setup_token', loginRes.data.setupToken)
        sessionStorage.setItem('setup_email', email)
        navigate('/first-login')
        return
      }

      if (loginRes.data.requiresTotp) {
        setPreAuthToken(loginRes.data.preAuthToken)
        setStep('totp')
        return
      }

      await finalizeLogin(loginRes.data, keyEncryptionKey!)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Login failed')
      setStep('credentials')
    }
  }

  async function handleTOTP(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setStep('decrypting')

    try {
      // Re-derive keys (still needed to decrypt masterKey after TOTP)
      const preflightRes = await api.get(`/auth/login/preflight?email=${encodeURIComponent(email)}`)
      const { kdfSalt } = preflightRes.data
      const { keyEncryptionKey } = await deriveInWorker(password, kdfSalt, preflightRes.data.loginKeySalt)

      const res = await api.post('/auth/login/2fa', {
        preAuthToken,
        code: totpCode,
      })

      await finalizeLogin(res.data, keyEncryptionKey)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Invalid code')
      setStep('totp')
    }
  }

  async function finalizeLogin(
    data: any,
    keyEncryptionKey: Uint8Array,
  ) {
    setStep('decrypting')

    // Decrypt masterKey client-side — server never sees it
    const masterKey = await decryptMasterKey(
      data.encryptedMasterKey,
      data.masterKeyNonce,
      keyEncryptionKey,
    )

    // Decrypt privateKey with masterKey
    const privateKey = await decryptPrivateKey(
      data.encryptedPrivateKey,
      data.privateKeyNonce,
      masterKey,
    )

    dispatch(setAuth({
      userId: data.userId,
      email,
      username: data.username,
      accessToken: data.accessToken,
      masterKey,
      privateKey,
      publicKey: data.publicKey,
      isAdmin: data.isAdmin,
      storageQuotaBytes: data.storageQuotaBytes,
      storageUsedBytes: data.storageUsedBytes,
    }))

    navigate('/drive')
  }

  if (step === 'deriving' || step === 'decrypting') {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <h2 style={styles.title}>
            {step === 'deriving' ? 'Deriving keys…' : 'Decrypting vault…'}
          </h2>
          <p style={styles.subtitle}>
            {step === 'deriving'
              ? 'Running Argon2id key derivation (this takes a moment)'
              : 'Decrypting your keys locally'}
          </p>
          <div style={styles.spinner} />
        </div>
      </div>
    )
  }

  if (step === 'totp') {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <h2 style={styles.title}>Two-factor authentication</h2>
          <p style={styles.subtitle}>Enter the 6-digit code from your authenticator app.</p>
          <form onSubmit={handleTOTP}>
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value)}
              style={{ ...styles.input, textAlign: 'center', letterSpacing: 8, fontSize: 24 }}
              placeholder="000000"
              autoFocus
              required
            />
            {error && <p style={styles.error}>{error}</p>}
            <button type="submit" style={styles.button}>Verify</button>
          </form>
        </div>
      </div>
    )
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.logo}>Depo</h1>
        <h2 style={styles.title}>Sign in</h2>
        <form onSubmit={handleLogin}>
          <div style={styles.field}>
            <label style={styles.label}>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={styles.input}
              required
              autoComplete="email"
            />
          </div>
          <div style={styles.field}>
            <label style={styles.label}>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={styles.input}
              required
              autoComplete="current-password"
            />
          </div>
          {error && <p style={styles.error}>{error}</p>}
          <button type="submit" style={styles.button}>Sign in</button>
        </form>
        <p style={styles.link}>
          <Link to="/recover" style={styles.a}>Forgot password?</Link>
        </p>
        <p style={styles.link}>
          No account? <Link to="/register" style={styles.a}>Create one</Link>
        </p>
      </div>
    </div>
  )
}

// Run KDF in worker, return as Uint8Arrays
function deriveInWorker(
  password: string,
  kdfSalt: string,
  loginKeySalt: string,
): Promise<{ keyEncryptionKey: Uint8Array; loginKey: Uint8Array }> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('../workers/kdf.worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (e) => {
      worker.terminate()
      if (e.data.type === 'error') reject(new Error(e.data.message))
      else resolve({
        keyEncryptionKey: new Uint8Array(Object.values(e.data.keyEncryptionKey)),
        loginKey: new Uint8Array(Object.values(e.data.loginKey)),
      })
    }
    worker.onerror = (e) => { worker.terminate(); reject(e) }
    worker.postMessage({ type: 'deriveKeys', password, kdfSalt, loginKeySalt })
  })
}

const styles: Record<string, React.CSSProperties> = {
  container: { display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: 16 },
  card: { background: '#1a1a1f', border: '1px solid #2a2a30', borderRadius: 12, padding: 40, width: '100%', maxWidth: 440 },
  logo: { margin: '0 0 8px', fontSize: 32, fontWeight: 700, color: '#7c3aed', letterSpacing: -1 },
  title: { margin: '0 0 8px', fontSize: 20, fontWeight: 600, color: '#e8e8ea' },
  subtitle: { margin: '0 0 24px', fontSize: 14, color: '#8888aa' },
  field: { marginBottom: 16 },
  label: { display: 'block', marginBottom: 6, fontSize: 13, color: '#8888aa', fontWeight: 500 },
  input: { width: '100%', padding: '10px 12px', background: '#0f0f11', border: '1px solid #2a2a30', borderRadius: 8, color: '#e8e8ea', fontSize: 14, outline: 'none' },
  button: { width: '100%', padding: '12px', background: '#7c3aed', color: '#fff', border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 600, cursor: 'pointer', marginTop: 8 },
  error: { color: '#ef4444', fontSize: 13, margin: '8px 0' },
  link: { textAlign: 'center', marginTop: 12, fontSize: 13, color: '#8888aa' },
  a: { color: '#7c3aed', textDecoration: 'none' },
  spinner: { width: 32, height: 32, border: '3px solid #2a2a30', borderTop: '3px solid #7c3aed', borderRadius: '50%', margin: '24px auto', animation: 'spin 1s linear infinite' },
}
