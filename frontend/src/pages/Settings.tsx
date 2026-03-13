import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppSelector, useAppDispatch } from '../store'
import { updateTotpEnabled } from '../store/authSlice'
import api from '../api/client'
import { QRCodeSVG } from 'qrcode.react'

export default function Settings() {
  const navigate = useNavigate()
  const dispatch = useAppDispatch()
  const auth = useAppSelector((s) => s.auth)

  const [totpSetup, setTotpSetup] = useState<{ secret: string; qrUri: string } | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  async function startTOTPSetup() {
    try {
      const res = await api.post('/user/2fa/setup')
      setTotpSetup(res.data)
      setError('')
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to start TOTP setup')
    }
  }

  async function verifyTOTP(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await api.post('/user/2fa/verify', { code: totpCode })
      dispatch(updateTotpEnabled(true))
      setTotpSetup(null)
      setTotpCode('')
      setSuccess('Two-factor authentication enabled')
    } catch (err: any) {
      setError(err.response?.data?.error || 'Invalid code')
    }
  }

  async function disableTOTP() {
    if (!confirm('Disable two-factor authentication? This reduces account security.')) return
    try {
      await api.delete('/user/2fa')
      dispatch(updateTotpEnabled(false))
      setSuccess('Two-factor authentication disabled')
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to disable TOTP')
    }
  }

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h1 style={styles.title}>Settings</h1>
        <button style={styles.backBtn} onClick={() => navigate('/drive')}>← Drive</button>
      </div>

      {error && <div style={styles.error}>{error}</div>}
      {success && <div style={styles.success}>{success}</div>}

      <div style={styles.section}>
        <h2 style={styles.sectionTitle}>Account</h2>
        <div style={styles.row}>
          <span style={styles.rowLabel}>Email</span>
          <span style={styles.rowValue}>{auth.email}</span>
        </div>
        <div style={styles.row}>
          <span style={styles.rowLabel}>Storage</span>
          <span style={styles.rowValue}>
            {formatBytes(auth.storageUsedBytes)} / {formatBytes(auth.storageQuotaBytes)}
          </span>
        </div>
      </div>

      <div style={styles.section}>
        <h2 style={styles.sectionTitle}>Two-Factor Authentication</h2>

        {auth.totpEnabled ? (
          <div>
            <p style={styles.statusOn}>TOTP is enabled</p>
            <button style={styles.dangerBtn} onClick={disableTOTP}>Disable TOTP</button>
          </div>
        ) : totpSetup ? (
          <div>
            <p style={styles.sub}>
              Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
            </p>
            <div style={styles.qrWrap}>
              <QRCodeSVG value={totpSetup.qrUri} size={180} bgColor="#1a1a1f" fgColor="#e8e8ea" />
            </div>
            <p style={styles.secretLabel}>Manual entry key:</p>
            <code style={styles.secretCode}>{totpSetup.secret}</code>
            <form onSubmit={verifyTOTP} style={{ marginTop: 20 }}>
              <label style={styles.label}>Enter the 6-digit code to confirm</label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                style={{ ...styles.input, letterSpacing: 8, textAlign: 'center', fontSize: 20 }}
                placeholder="000000"
                autoFocus
                required
              />
              <button type="submit" style={styles.primaryBtn}>Enable TOTP</button>
            </form>
          </div>
        ) : (
          <div>
            <p style={styles.sub}>Add an extra layer of security with an authenticator app.</p>
            <button style={styles.primaryBtn} onClick={startTOTPSetup}>Set up TOTP</button>
          </div>
        )}
      </div>

      <div style={styles.section}>
        <h2 style={styles.sectionTitle}>Encryption</h2>
        <p style={styles.sub}>
          All files are encrypted client-side using XChaCha20-Poly1305. Your master key and private key
          are derived from your password using Argon2id and are never sent to the server in plaintext.
          The server stores only ciphertext it cannot decrypt.
        </p>
        <p style={styles.sub}>
          To change your password, use the <a href="/recover" style={styles.a}>account recovery</a> flow
          with your 24-word mnemonic.
        </p>
      </div>
    </div>
  )
}

function formatBytes(bytes: number): string {
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(0)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`
}

const styles: Record<string, React.CSSProperties> = {
  container: { maxWidth: 640, margin: '0 auto', padding: 32 },
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 32 },
  title: { margin: 0, fontSize: 24, fontWeight: 700 },
  backBtn: { padding: '8px 16px', background: '#1e1e2a', border: '1px solid #2a2a30', color: '#e8e8ea', borderRadius: 8, cursor: 'pointer', fontSize: 13 },
  section: { background: '#1a1a1f', border: '1px solid #2a2a30', borderRadius: 12, padding: 24, marginBottom: 20 },
  sectionTitle: { margin: '0 0 16px', fontSize: 16, fontWeight: 600 },
  row: { display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #1e1e2a' },
  rowLabel: { fontSize: 13, color: '#8888aa' },
  rowValue: { fontSize: 13, color: '#e8e8ea' },
  sub: { fontSize: 13, color: '#8888aa', margin: '0 0 16px', lineHeight: 1.6 },
  statusOn: { color: '#22c55e', fontSize: 14, marginBottom: 12 },
  label: { display: 'block', marginBottom: 6, fontSize: 13, color: '#8888aa', fontWeight: 500 },
  input: { width: '100%', padding: '10px 12px', background: '#0f0f11', border: '1px solid #2a2a30', borderRadius: 8, color: '#e8e8ea', fontSize: 14, outline: 'none', marginBottom: 12 },
  primaryBtn: { padding: '10px 20px', background: '#7c3aed', color: '#fff', border: 'none', borderRadius: 8, cursor: 'pointer', fontSize: 14, fontWeight: 600 },
  dangerBtn: { padding: '10px 20px', background: 'transparent', color: '#ef4444', border: '1px solid #ef444440', borderRadius: 8, cursor: 'pointer', fontSize: 14 },
  error: { background: '#2d1a1a', border: '1px solid #ef444440', borderRadius: 8, padding: '12px 16px', marginBottom: 16, color: '#ef4444', fontSize: 13 },
  success: { background: '#1a2d1a', border: '1px solid #22c55e40', borderRadius: 8, padding: '12px 16px', marginBottom: 16, color: '#22c55e', fontSize: 13 },
  qrWrap: { background: '#1a1a1f', padding: 16, borderRadius: 8, display: 'inline-block', marginBottom: 16 },
  secretLabel: { fontSize: 12, color: '#8888aa', margin: '0 0 4px' },
  secretCode: { display: 'block', background: '#0f0f11', padding: '8px 12px', borderRadius: 6, fontSize: 13, fontFamily: 'monospace', color: '#a78bfa', letterSpacing: 2 },
  a: { color: '#7c3aed' },
}
