import { useState, useRef, useCallback, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import { toBase64 } from '../crypto'
import type { RegistrationKeys } from '../crypto'
import zxcvbn from 'zxcvbn'
import { KutupLogo } from '../components/KutupLogo'

type Step = 'form' | 'generating' | 'mnemonic' | 'confirm' | 'submitting' | 'done'

export default function Register() {
  const navigate = useNavigate()
  const [step, setStep] = useState<Step>('form')
  const [registrationEnabled, setRegistrationEnabled] = useState<boolean | null>(null)

  useEffect(() => {
    api.get('/auth/settings').then((res) => {
      setRegistrationEnabled(res.data.registrationEnabled)
    }).catch(() => {
      setRegistrationEnabled(true) // fail open
    })
  }, [])
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [passwordConfirm, setPasswordConfirm] = useState('')
  const [error, setError] = useState('')
  const [keys, setKeys] = useState<RegistrationKeys | null>(null)
  const [mnemonicConfirm, setMnemonicConfirm] = useState('')
  const [copied, setCopied] = useState(false)
  const workerRef = useRef<Worker | null>(null)

  const passwordStrength = zxcvbn(password)
  const strengthLabel = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong']

  async function handleSubmitForm(e: React.FormEvent) {
    e.preventDefault()
    setError('')

    if (!/^[a-z0-9_-]{3,32}$/.test(username)) {
      setError('Invalid username: 3-32 chars, lowercase letters, numbers, _ and -')
      return
    }
    if (password !== passwordConfirm) {
      setError('Passwords do not match')
      return
    }
    if (passwordStrength.score < 2) {
      setError('Password is too weak')
      return
    }

    setStep('generating')

    // Run KDF in Web Worker to avoid blocking UI
    const worker = new Worker(new URL('../workers/kdf.worker.ts', import.meta.url), { type: 'module' })
    workerRef.current = worker

    worker.onmessage = (e) => {
      const data = e.data
      if (data.type === 'error') {
        setError(data.message)
        setStep('form')
        worker.terminate()
        return
      }
      if (data.type === 'register') {
        setKeys(data.keys)
        setStep('mnemonic')
        worker.terminate()
      }
    }

    worker.onerror = (e) => {
      setError(e.message)
      setStep('form')
    }

    worker.postMessage({ type: 'register', password })
  }

  const handleCopy = useCallback(() => {
    if (!keys) return
    const text = keys.mnemonic
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      })
    } else {
      // fallback for http (non-secure context)
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.focus()
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }, [keys])

  const handleDownload = useCallback(() => {
    if (!keys) return
    // Plain space-separated phrase so it can be pasted directly into the confirmation box
    const blob = new Blob([keys.mnemonic], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'kutup-recovery-phrase.txt'
    a.click()
    URL.revokeObjectURL(url)
  }, [keys])

  async function handleConfirmMnemonic(e: React.FormEvent) {
    e.preventDefault()
    if (!keys) return

    // Strip any leading numbers/dots (e.g. "1. word" → "word") then normalise whitespace
    const normalizedInput = mnemonicConfirm
      .trim()
      .toLowerCase()
      .replace(/\b\d+\.\s*/g, '')
      .replace(/\s+/g, ' ')
      .trim()
    const normalizedExpected = keys.mnemonic.trim().toLowerCase()

    if (normalizedInput !== normalizedExpected) {
      setError('Mnemonic does not match. Please check each word carefully.')
      return
    }

    setStep('submitting')
    setError('')

    try {
      await api.post('/auth/register', {
        email,
        username,
        loginKey: keys.loginKey,
        encryptedMasterKey: keys.encryptedMasterKey,
        masterKeyNonce: keys.masterKeyNonce,
        encryptedRecoveryKey: keys.encryptedRecoveryKey,
        recoveryKeyNonce: keys.recoveryKeyNonce,
        encryptedPrivateKey: keys.encryptedPrivateKey,
        privateKeyNonce: keys.privateKeyNonce,
        publicKey: keys.publicKey,
        kdfSalt: keys.kdfSalt,
        loginKeySalt: keys.loginKeySalt,
        recoveryProof: keys.recoveryKey,
      })
      setStep('done')
    } catch (err: any) {
      setError(err.response?.data?.error || 'Registration failed')
      setStep('mnemonic')
    }
  }

  if (registrationEnabled === null) {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <div style={styles.spinner} />
        </div>
      </div>
    )
  }

  if (registrationEnabled === false) {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, marginBottom: 8 }}>
            <KutupLogo size={36} />
            <h1 style={styles.logo}>Kutup</h1>
          </div>
          <h2 style={styles.title}>Registration disabled</h2>
          <p style={styles.subtitle}>
            Public registration is currently disabled.<br />
            Contact your administrator to get access.
          </p>
          <p style={styles.link}>
            <Link to="/login" style={styles.a}>Back to sign in</Link>
          </p>
        </div>
      </div>
    )
  }

  if (step === 'generating') {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <h2 style={styles.title}>Generating your keys…</h2>
          <p style={styles.subtitle}>This takes a moment (Argon2id key derivation)</p>
          <div style={styles.spinner} />
        </div>
      </div>
    )
  }

  if (step === 'mnemonic' && keys) {
    return (
      <div style={styles.container}>
        <div style={{ ...styles.card, maxWidth: 600 }}>
          <h2 style={styles.title}>Save your Recovery Phrase</h2>
          <p style={{ ...styles.subtitle, color: '#f59e0b' }}>
            This 24-word phrase is shown ONCE. Write it down and store it safely.
            It is the only way to recover your account if you forget your password.
          </p>
          <div style={styles.mnemonicGrid}>
            {keys.mnemonic.split(' ').map((word, i) => (
              <div key={i} style={styles.mnemonicWord}>
                <span style={styles.mnemonicNum}>{i + 1}.</span> {word}
              </div>
            ))}
          </div>
          <div style={styles.mnemonicActions}>
            <button style={styles.secondaryButton} onClick={handleCopy}>
              {copied ? 'Copied!' : 'Copy to clipboard'}
            </button>
            <button style={styles.secondaryButton} onClick={handleDownload}>
              Download as file
            </button>
          </div>
          <button
            style={styles.button}
            onClick={() => setStep('confirm')}
          >
            I've saved my recovery phrase
          </button>
        </div>
      </div>
    )
  }

  if (step === 'confirm') {
    return (
      <div style={styles.container}>
        <div style={{ ...styles.card, maxWidth: 600 }}>
          <h2 style={styles.title}>Confirm Recovery Phrase</h2>
          <p style={styles.subtitle}>Type all 24 words to confirm you've saved them.</p>
          <form onSubmit={handleConfirmMnemonic}>
            <textarea
              style={styles.textarea}
              value={mnemonicConfirm}
              onChange={(e) => setMnemonicConfirm(e.target.value)}
              placeholder="Enter all 24 words separated by spaces..."
              rows={5}
              required
            />
            {error && <p style={styles.error}>{error}</p>}
            <button type="submit" style={styles.button}>
              Complete Registration
            </button>
          </form>
        </div>
      </div>
    )
  }

  if (step === 'submitting') {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <h2 style={styles.title}>Creating account…</h2>
          <div style={styles.spinner} />
        </div>
      </div>
    )
  }

  if (step === 'done') {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <h2 style={styles.title}>Account created!</h2>
          <p style={styles.subtitle}>Your encrypted account is ready.</p>
          <button style={styles.button} onClick={() => navigate('/login')}>
            Sign in
          </button>
        </div>
      </div>
    )
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, marginBottom: 8 }}>
          <KutupLogo size={36} />
          <h1 style={styles.logo}>Kutup</h1>
        </div>
        <h2 style={styles.title}>Create account</h2>
        <form onSubmit={handleSubmitForm}>
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
            <label style={styles.label}>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value.toLowerCase())}
              style={styles.input}
              required
              autoComplete="username"
              pattern="^[a-z0-9_-]{3,32}$"
              placeholder="e.g. alice_42"
            />
            <span style={{ fontSize: 11, color: '#4e7a97', marginTop: 4, display: 'block' }}>
              3-32 chars, lowercase letters, numbers, _ and -
            </span>
          </div>
          <div style={styles.field}>
            <label style={styles.label}>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={styles.input}
              required
              autoComplete="new-password"
            />
            {password && (
              <div style={styles.strengthBar}>
                <div
                  style={{
                    ...styles.strengthFill,
                    width: `${(passwordStrength.score + 1) * 20}%`,
                    background: ['#ef4444','#f97316','#eab308','#22c55e','#16a34a'][passwordStrength.score],
                  }}
                />
                <span style={styles.strengthLabel}>{strengthLabel[passwordStrength.score]}</span>
              </div>
            )}
          </div>
          <div style={styles.field}>
            <label style={styles.label}>Confirm Password</label>
            <input
              type="password"
              value={passwordConfirm}
              onChange={(e) => setPasswordConfirm(e.target.value)}
              style={styles.input}
              required
              autoComplete="new-password"
            />
          </div>
          {error && <p style={styles.error}>{error}</p>}
          <button type="submit" style={styles.button}>
            Create account
          </button>
        </form>
        <p style={styles.link}>
          Already have an account? <Link to="/login" style={styles.a}>Sign in</Link>
        </p>
      </div>
    </div>
  )
}

const styles: Record<string, React.CSSProperties> = {
  container: { display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: 16 },
  card: { background: '#0c1a27', border: '1px solid #1a3045', borderRadius: 12, padding: 40, width: '100%', maxWidth: 440 },
  logo: { margin: 0, fontSize: 32, fontWeight: 700, color: '#38bdf8', letterSpacing: -1 },
  title: { margin: '0 0 8px', fontSize: 20, fontWeight: 600, color: '#d4ecf7' },
  subtitle: { margin: '0 0 24px', fontSize: 14, color: '#4e7a97' },
  field: { marginBottom: 16 },
  label: { display: 'block', marginBottom: 6, fontSize: 13, color: '#4e7a97', fontWeight: 500 },
  input: { width: '100%', padding: '10px 12px', background: '#060d14', border: '1px solid #1a3045', borderRadius: 8, color: '#d4ecf7', fontSize: 14, outline: 'none' },
  textarea: { width: '100%', padding: '10px 12px', background: '#060d14', border: '1px solid #1a3045', borderRadius: 8, color: '#d4ecf7', fontSize: 14, outline: 'none', resize: 'vertical', fontFamily: 'monospace' },
  button: { width: '100%', padding: '12px', background: '#0ea5e9', color: '#fff', border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 600, cursor: 'pointer', marginTop: 8 },
  error: { color: '#ef4444', fontSize: 13, margin: '8px 0' },
  link: { textAlign: 'center', marginTop: 20, fontSize: 13, color: '#4e7a97' },
  a: { color: '#0ea5e9', textDecoration: 'none' },
  spinner: { width: 32, height: 32, border: '3px solid #1a3045', borderTop: '3px solid #0ea5e9', borderRadius: '50%', margin: '24px auto', animation: 'spin 1s linear infinite' },
  strengthBar: { marginTop: 6, background: '#1a3045', borderRadius: 4, height: 4, overflow: 'hidden', position: 'relative' },
  strengthFill: { height: '100%', borderRadius: 4, transition: 'width 0.3s, background 0.3s' },
  strengthLabel: { position: 'absolute', right: 0, top: 6, fontSize: 11, color: '#4e7a97' },
  mnemonicGrid: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginBottom: 12, background: '#060d14', padding: 16, borderRadius: 8 },
  mnemonicActions: { display: 'flex', gap: 8, marginBottom: 16 },
  secondaryButton: { flex: 1, padding: '9px 12px', background: 'transparent', color: '#4e7a97', border: '1px solid #1a3045', borderRadius: 8, fontSize: 13, fontWeight: 500, cursor: 'pointer' },
  mnemonicWord: { padding: '6px 8px', background: '#0c1a27', borderRadius: 6, fontSize: 13, color: '#d4ecf7', fontFamily: 'monospace' },
  mnemonicNum: { color: '#4e7a97', fontSize: 11 },
}
