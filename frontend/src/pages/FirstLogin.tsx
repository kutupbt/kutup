import { useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppDispatch } from '../store'
import { setAuth } from '../store/authSlice'
import api from '../api/client'
import { toBase64 } from '../crypto'
import type { RegistrationKeys } from '../crypto'
import zxcvbn from 'zxcvbn'

type Step = 'form' | 'generating' | 'mnemonic' | 'confirm' | 'submitting'

export default function FirstLogin() {
  const navigate = useNavigate()
  const dispatch = useAppDispatch()
  const [step, setStep] = useState<Step>('form')
  const [password, setPassword] = useState('')
  const [passwordConfirm, setPasswordConfirm] = useState('')
  const [mnemonicConfirm, setMnemonicConfirm] = useState('')
  const [keys, setKeys] = useState<RegistrationKeys | null>(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)

  const email = sessionStorage.getItem('setup_email') || ''
  const setupToken = sessionStorage.getItem('setup_token') || ''

  const passwordStrength = zxcvbn(password)
  const strengthLabel = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong']

  useEffect(() => {
    if (!setupToken) navigate('/login')
  }, [setupToken, navigate])

  async function handleSetPassword(e: React.FormEvent) {
    e.preventDefault()
    setError('')

    if (password !== passwordConfirm) {
      setError('Passwords do not match')
      return
    }
    if (passwordStrength.score < 2) {
      setError('Password is too weak')
      return
    }

    setStep('generating')

    const worker = new Worker(new URL('../workers/kdf.worker.ts', import.meta.url), { type: 'module' })
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
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(keys.mnemonic).then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      })
    } else {
      const ta = document.createElement('textarea')
      ta.value = keys.mnemonic
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
    const blob = new Blob([keys.mnemonic], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'depo-recovery-phrase.txt'
    a.click()
    URL.revokeObjectURL(url)
  }, [keys])

  async function handleConfirmMnemonic(e: React.FormEvent) {
    e.preventDefault()
    if (!keys) return

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
      const res = await api.post(
        '/auth/complete-setup',
        {
          email,
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
        },
        { headers: { Authorization: `Bearer ${setupToken}` } },
      )

      sessionStorage.removeItem('setup_token')
      sessionStorage.removeItem('setup_email')

      dispatch(setAuth({
        userId: res.data.userId,
        email,
        username: res.data.username,
        accessToken: res.data.accessToken,
        masterKey: keys.masterKey,
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
        isAdmin: res.data.isAdmin,
        storageQuotaBytes: res.data.storageQuotaBytes,
        storageUsedBytes: res.data.storageUsedBytes,
      }))

      navigate('/drive')
    } catch (err: any) {
      setError(err.response?.data?.error || 'Setup failed')
      setStep('mnemonic')
    }
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
          <button style={styles.button} onClick={() => setStep('confirm')}>
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
            <button type="submit" style={styles.button}>Complete setup</button>
          </form>
        </div>
      </div>
    )
  }

  if (step === 'submitting') {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <h2 style={styles.title}>Finishing setup…</h2>
          <div style={styles.spinner} />
        </div>
      </div>
    )
  }

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.logo}>Depo</h1>
        <h2 style={styles.title}>Set your password</h2>
        <p style={styles.subtitle}>
          Welcome! Choose a strong password and you'll be shown a 24-word recovery phrase.
          {email && <><br /><span style={{ color: '#a78bfa' }}>{email}</span></>}
        </p>
        <form onSubmit={handleSetPassword}>
          <div style={styles.field}>
            <label style={styles.label}>New password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={styles.input}
              required
              autoComplete="new-password"
              autoFocus
            />
            {password && (
              <div style={styles.strengthBar}>
                <div
                  style={{
                    ...styles.strengthFill,
                    width: `${(passwordStrength.score + 1) * 20}%`,
                    background: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#16a34a'][passwordStrength.score],
                  }}
                />
                <span style={styles.strengthLabel}>{strengthLabel[passwordStrength.score]}</span>
              </div>
            )}
          </div>
          <div style={styles.field}>
            <label style={styles.label}>Confirm password</label>
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
          <button type="submit" style={styles.button}>Continue</button>
        </form>
      </div>
    </div>
  )
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
  textarea: { width: '100%', padding: '10px 12px', background: '#0f0f11', border: '1px solid #2a2a30', borderRadius: 8, color: '#e8e8ea', fontSize: 14, outline: 'none', resize: 'vertical', fontFamily: 'monospace' },
  button: { width: '100%', padding: '12px', background: '#7c3aed', color: '#fff', border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 600, cursor: 'pointer', marginTop: 8 },
  secondaryButton: { flex: 1, padding: '9px 12px', background: 'transparent', color: '#8888aa', border: '1px solid #2a2a30', borderRadius: 8, fontSize: 13, fontWeight: 500, cursor: 'pointer' },
  error: { color: '#ef4444', fontSize: 13, margin: '8px 0' },
  spinner: { width: 32, height: 32, border: '3px solid #2a2a30', borderTop: '3px solid #7c3aed', borderRadius: '50%', margin: '24px auto', animation: 'spin 1s linear infinite' },
  strengthBar: { marginTop: 6, background: '#2a2a30', borderRadius: 4, height: 4, overflow: 'hidden', position: 'relative' },
  strengthFill: { height: '100%', borderRadius: 4, transition: 'width 0.3s, background 0.3s' },
  strengthLabel: { position: 'absolute', right: 0, top: 6, fontSize: 11, color: '#8888aa' },
  mnemonicGrid: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginBottom: 12, background: '#0f0f11', padding: 16, borderRadius: 8 },
  mnemonicActions: { display: 'flex', gap: 8, marginBottom: 16 },
  mnemonicWord: { padding: '6px 8px', background: '#1a1a1f', borderRadius: 6, fontSize: 13, color: '#e8e8ea', fontFamily: 'monospace' },
  mnemonicNum: { color: '#8888aa', fontSize: 11 },
}
