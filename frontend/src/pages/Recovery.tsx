// Account recovery via BIP39 mnemonic.
// Flow: mnemonic → recoveryKey → decrypt encryptedMasterKey_recovery → re-encrypt with new password
// TOTP bypass is intentional: mnemonic IS the second factor.
import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import { KutupLogo } from '../components/KutupLogo'
import {
  decodeMnemonic, validateMnemonic,
  decrypt, encrypt, generateKey,
  deriveKeyEncryptionKey, deriveLoginKey, generateKDFSalt,
  toBase64, fromBase64,
} from '../crypto'
import zxcvbn from 'zxcvbn'

type Step = 'form' | 'deriving' | 'done'

export default function Recovery() {
  const navigate = useNavigate()
  const [step, setStep] = useState<Step>('form')
  const [email, setEmail] = useState('')
  const [mnemonic, setMnemonic] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newPasswordConfirm, setNewPasswordConfirm] = useState('')
  const [error, setError] = useState('')

  const passwordStrength = zxcvbn(newPassword)

  async function handleRecover(e: React.FormEvent) {
    e.preventDefault()
    setError('')

    if (!validateMnemonic(mnemonic)) {
      setError('Invalid recovery phrase — check for typos')
      return
    }
    if (newPassword !== newPasswordConfirm) {
      setError('Passwords do not match')
      return
    }
    if (passwordStrength.score < 2) {
      setError('New password is too weak')
      return
    }

    setStep('deriving')

    try {
      // 1. Fetch encrypted recovery key material from server
      const preflightRes = await api.get(`/auth/login/preflight?email=${encodeURIComponent(email)}`)
      // We need the encrypted recovery key — fetch via a dedicated endpoint
      // For recovery, we need the encryptedRecoveryKey and its nonce
      // This requires a separate API call that returns only the recovery-specific data
      const recoveryDataRes = await api.get(`/auth/recover/preflight?email=${encodeURIComponent(email)}`)
      const { encryptedRecoveryKey, recoveryKeyNonce, encryptedPrivateKey, privateKeyNonce } = recoveryDataRes.data

      // 2. Decode mnemonic → recoveryKey
      const recoveryKey = decodeMnemonic(mnemonic.trim().toLowerCase())

      // 3. Decrypt masterKey using recoveryKey
      const masterKey = await decrypt(
        fromBase64(encryptedRecoveryKey),
        fromBase64(recoveryKeyNonce),
        recoveryKey,
      )

      // 4. Generate new salts and derive new keys from new password
      const newKdfSalt = await generateKDFSalt()
      const newLoginKeySalt = await generateKDFSalt()
      const newKeyEncKey = await deriveKeyEncryptionKey(newPassword, newKdfSalt)
      const newLoginKey = await deriveLoginKey(newPassword, newLoginKeySalt)

      // 5. Re-encrypt masterKey with new keyEncryptionKey
      const newEncMK = await encrypt(masterKey, newKeyEncKey)

      // 6. Submit recovery
      await api.post('/auth/recover', {
        email,
        newLoginKey: toBase64(newLoginKey),
        newEncryptedMasterKey: toBase64(newEncMK.ciphertext),
        newMasterKeyNonce: toBase64(newEncMK.nonce),
        newKdfSalt: toBase64(newKdfSalt),
        newLoginKeySalt: toBase64(newLoginKeySalt),
        recoveryProof: toBase64(recoveryKey), // Proof: we could decrypt the masterKey
      })

      setStep('done')
    } catch (err: any) {
      setError(err.response?.data?.error || err.message || 'Recovery failed')
      setStep('form')
    }
  }

  if (step === 'deriving') {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <h2 style={styles.title}>Recovering account…</h2>
          <p style={styles.subtitle}>Deriving keys and re-encrypting vault</p>
          <div style={styles.spinner} />
        </div>
      </div>
    )
  }

  if (step === 'done') {
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <h2 style={styles.title}>Account recovered!</h2>
          <p style={styles.subtitle}>Your password has been reset. Sign in with your new password.</p>
          <button style={styles.button} onClick={() => navigate('/login')}>Sign in</button>
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
        <h2 style={styles.title}>Recover account</h2>
        <p style={styles.subtitle}>
          Enter your 24-word recovery phrase and a new password.
          Note: 2FA is bypassed during recovery — the recovery phrase is your second factor.
        </p>
        <form onSubmit={handleRecover}>
          <div style={styles.field}>
            <label style={styles.label}>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={styles.input}
              required
            />
          </div>
          <div style={styles.field}>
            <label style={styles.label}>Recovery Phrase (24 words)</label>
            <textarea
              value={mnemonic}
              onChange={(e) => setMnemonic(e.target.value)}
              style={styles.textarea}
              placeholder="word1 word2 word3 ... word24"
              rows={4}
              required
            />
          </div>
          <div style={styles.field}>
            <label style={styles.label}>New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              style={styles.input}
              required
            />
            {newPassword && (
              <div style={{ marginTop: 4, fontSize: 12, color: ['#ef4444','#f97316','#eab308','#22c55e','#16a34a'][passwordStrength.score] }}>
                Password strength: {['Very weak','Weak','Fair','Strong','Very strong'][passwordStrength.score]}
              </div>
            )}
          </div>
          <div style={styles.field}>
            <label style={styles.label}>Confirm New Password</label>
            <input
              type="password"
              value={newPasswordConfirm}
              onChange={(e) => setNewPasswordConfirm(e.target.value)}
              style={styles.input}
              required
            />
          </div>
          {error && <p style={styles.error}>{error}</p>}
          <button type="submit" style={styles.button}>Recover account</button>
        </form>
        <p style={styles.link}>
          <Link to="/login" style={styles.a}>Back to sign in</Link>
        </p>
      </div>
    </div>
  )
}

const styles: Record<string, React.CSSProperties> = {
  container: { display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: 16 },
  card: { background: '#0c1a27', border: '1px solid #1a3045', borderRadius: 12, padding: 40, width: '100%', maxWidth: 500 },
  logo: { margin: 0, fontSize: 32, fontWeight: 700, color: '#38bdf8', letterSpacing: -1 },
  title: { margin: '0 0 8px', fontSize: 20, fontWeight: 600, color: '#d4ecf7' },
  subtitle: { margin: '0 0 24px', fontSize: 14, color: '#4e7a97' },
  field: { marginBottom: 16 },
  label: { display: 'block', marginBottom: 6, fontSize: 13, color: '#4e7a97', fontWeight: 500 },
  input: { width: '100%', padding: '10px 12px', background: '#060d14', border: '1px solid #1a3045', borderRadius: 8, color: '#d4ecf7', fontSize: 14, outline: 'none' },
  textarea: { width: '100%', padding: '10px 12px', background: '#060d14', border: '1px solid #1a3045', borderRadius: 8, color: '#d4ecf7', fontSize: 14, outline: 'none', resize: 'vertical', fontFamily: 'monospace' },
  button: { width: '100%', padding: '12px', background: '#0ea5e9', color: '#fff', border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 600, cursor: 'pointer', marginTop: 8 },
  error: { color: '#ef4444', fontSize: 13, margin: '8px 0' },
  link: { textAlign: 'center', marginTop: 16, fontSize: 13, color: '#4e7a97' },
  a: { color: '#0ea5e9', textDecoration: 'none' },
  spinner: { width: 32, height: 32, border: '3px solid #1a3045', borderTop: '3px solid #0ea5e9', borderRadius: '50%', margin: '24px auto', animation: 'spin 1s linear infinite' },
}
