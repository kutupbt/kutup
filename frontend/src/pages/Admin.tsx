import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppSelector } from '../store'
import { selectIsAdmin, selectIsLoggedIn } from '../store/authSlice'
import api from '../api/client'

interface User {
  id: string
  email: string
  username: string
  storageQuotaBytes: number
  storageUsedBytes: number
  isAdmin: boolean
  isActive: boolean
  totpEnabled: boolean
  createdAt: string
}

interface Stats {
  totalUsers: number
  activeUsers: number
  totalFiles: number
  totalStorageUsedBytes: number
  totalCollections: number
}

export default function Admin() {
  const navigate = useNavigate()
  const isLoggedIn = useAppSelector(selectIsLoggedIn)
  const isAdmin = useAppSelector(selectIsAdmin)

  const [users, setUsers] = useState<User[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [editQuota, setEditQuota] = useState<{ userId: string; gb: string } | null>(null)

  // Registration toggle
  const [registrationEnabled, setRegistrationEnabled] = useState(true)

  // Create user modal
  const [showCreateUser, setShowCreateUser] = useState(false)
  const [createEmail, setCreateEmail] = useState('')
  const [createUsername, setCreateUsername] = useState('')
  const [createPassword, setCreatePassword] = useState('')
  const [createQuotaGB, setCreateQuotaGB] = useState('10')
  const [createLoading, setCreateLoading] = useState(false)
  const [createError, setCreateError] = useState('')

  useEffect(() => {
    if (!isLoggedIn) navigate('/login')
    else if (!isAdmin) navigate('/drive')
    else loadData()
  }, [isLoggedIn, isAdmin])

  async function loadData() {
    setLoading(true)
    try {
      const [usersRes, statsRes, settingsRes] = await Promise.all([
        api.get('/admin/users'),
        api.get('/admin/stats'),
        api.get('/admin/settings'),
      ])
      setUsers(usersRes.data)
      setStats(statsRes.data)
      setRegistrationEnabled(settingsRes.data.registrationEnabled)
    } catch (err) {
      setError('Failed to load admin data')
    } finally {
      setLoading(false)
    }
  }

  async function toggleActive(user: User) {
    try {
      await api.put(`/admin/users/${user.id}`, { isActive: !user.isActive })
      setUsers((prev) =>
        prev.map((u) => u.id === user.id ? { ...u, isActive: !u.isActive } : u),
      )
    } catch {
      setError('Update failed')
    }
  }

  async function updateQuota(userId: string, gb: number) {
    try {
      await api.put(`/admin/users/${userId}`, { storageQuotaBytes: gb * 1024 * 1024 * 1024 })
      setUsers((prev) =>
        prev.map((u) => u.id === userId ? { ...u, storageQuotaBytes: gb * 1024 * 1024 * 1024 } : u),
      )
      setEditQuota(null)
    } catch {
      setError('Quota update failed')
    }
  }

  async function deleteUser(user: User) {
    if (!confirm(`Permanently delete ${user.email}? This cannot be undone.`)) return
    try {
      await api.delete(`/admin/users/${user.id}`)
      setUsers((prev) => prev.filter((u) => u.id !== user.id))
    } catch {
      setError('Delete failed')
    }
  }

  async function toggleRegistration() {
    const newVal = !registrationEnabled
    try {
      await api.put('/admin/settings', { registrationEnabled: newVal })
      setRegistrationEnabled(newVal)
    } catch {
      setError('Settings update failed')
    }
  }

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault()
    setCreateError('')
    if (!/^[a-z0-9_-]{3,32}$/.test(createUsername)) {
      setCreateError('Invalid username: 3-32 chars, lowercase letters, numbers, _ and -')
      return
    }
    setCreateLoading(true)
    try {
      await api.post('/admin/users', {
        email: createEmail,
        username: createUsername,
        tempPassword: createPassword,
        storageQuotaBytes: parseFloat(createQuotaGB) * 1024 * 1024 * 1024,
      })
      setShowCreateUser(false)
      setCreateEmail('')
      setCreateUsername('')
      setCreatePassword('')
      setCreateQuotaGB('10')
      await loadData()
    } catch (err: any) {
      setCreateError(err.response?.data?.error || 'Failed to create user')
    } finally {
      setCreateLoading(false)
    }
  }

  if (loading) {
    return (
      <div style={styles.container}>
        <div style={styles.spinner} />
      </div>
    )
  }

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h1 style={styles.title}>Admin Panel</h1>
        <div style={{ display: 'flex', gap: 8 }}>
          <button style={styles.backBtn} onClick={() => setShowCreateUser(true)}>+ Create user</button>
          <button style={styles.backBtn} onClick={() => navigate('/drive')}>← Drive</button>
        </div>
      </div>

      {error && <div style={styles.error}>{error}</div>}

      {stats && (
        <div style={styles.statsGrid}>
          <div style={styles.stat}><div style={styles.statNum}>{stats.totalUsers}</div><div style={styles.statLabel}>Total users</div></div>
          <div style={styles.stat}><div style={styles.statNum}>{stats.activeUsers}</div><div style={styles.statLabel}>Active users</div></div>
          <div style={styles.stat}><div style={styles.statNum}>{stats.totalFiles}</div><div style={styles.statLabel}>Total files</div></div>
          <div style={styles.stat}><div style={styles.statNum}>{stats.totalCollections}</div><div style={styles.statLabel}>Collections</div></div>
          <div style={styles.stat}><div style={styles.statNum}>{formatBytes(stats.totalStorageUsedBytes)}</div><div style={styles.statLabel}>Storage used</div></div>
        </div>
      )}

      <div style={styles.settingsRow}>
        <span style={styles.settingsLabel}>Public registration</span>
        <button
          style={{
            ...styles.toggleBtn,
            background: registrationEnabled ? '#22c55e20' : '#ef444420',
            color: registrationEnabled ? '#22c55e' : '#ef4444',
            border: `1px solid ${registrationEnabled ? '#22c55e40' : '#ef444440'}`,
          }}
          onClick={toggleRegistration}
        >
          {registrationEnabled ? 'Enabled' : 'Disabled'}
        </button>
      </div>

      <div style={styles.note}>
        Note: File names and contents are encrypted. Admins cannot see user data.
      </div>

      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.th}>Email</th>
            <th style={styles.th}>Username</th>
            <th style={styles.th}>Quota</th>
            <th style={styles.th}>Used</th>
            <th style={styles.th}>Status</th>
            <th style={styles.th}>TOTP</th>
            <th style={styles.th}>Joined</th>
            <th style={styles.th}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id} style={styles.tr}>
              <td style={styles.td}>
                {user.email}
                {user.isAdmin && <span style={styles.badge}>admin</span>}
              </td>
              <td style={styles.td}>{user.username}</td>
              <td style={styles.td}>
                {editQuota?.userId === user.id ? (
                  <span style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                    <input
                      type="number"
                      value={editQuota.gb}
                      onChange={(e) => setEditQuota({ ...editQuota, gb: e.target.value })}
                      style={{ ...styles.input, width: 60 }}
                    />
                    GB
                    <button style={styles.smallBtn} onClick={() => updateQuota(user.id, parseFloat(editQuota.gb))}>✓</button>
                    <button style={styles.smallBtn} onClick={() => setEditQuota(null)}>×</button>
                  </span>
                ) : (
                  <span
                    style={{ cursor: 'pointer', textDecoration: 'underline dotted' }}
                    onClick={() => setEditQuota({ userId: user.id, gb: String(user.storageQuotaBytes / 1024 / 1024 / 1024) })}
                  >
                    {formatBytes(user.storageQuotaBytes)}
                  </span>
                )}
              </td>
              <td style={styles.td}>{formatBytes(user.storageUsedBytes)}</td>
              <td style={styles.td}>
                <span style={{ color: user.isActive ? '#22c55e' : '#ef4444' }}>
                  {user.isActive ? 'Active' : 'Disabled'}
                </span>
              </td>
              <td style={styles.td}>{user.totpEnabled ? '✓' : '—'}</td>
              <td style={styles.td}>{new Date(user.createdAt).toLocaleDateString()}</td>
              <td style={styles.td}>
                <button style={styles.smallBtn} onClick={() => toggleActive(user)}>
                  {user.isActive ? 'Disable' : 'Enable'}
                </button>
                <button style={{ ...styles.smallBtn, color: '#ef4444' }} onClick={() => deleteUser(user)}>
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {showCreateUser && (
        <div style={styles.modalOverlay} onClick={() => setShowCreateUser(false)}>
          <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
            <h3 style={styles.modalTitle}>Create user</h3>
            <p style={styles.modalSubtitle}>
              The user will set their own password and recovery phrase on first login.
            </p>
            <form onSubmit={handleCreateUser}>
              <div style={styles.field}>
                <label style={styles.label}>Email</label>
                <input
                  type="email"
                  value={createEmail}
                  onChange={(e) => setCreateEmail(e.target.value)}
                  style={styles.input}
                  required
                  autoFocus
                />
              </div>
              <div style={styles.field}>
                <label style={styles.label}>Username</label>
                <input
                  type="text"
                  value={createUsername}
                  onChange={(e) => setCreateUsername(e.target.value.toLowerCase())}
                  style={styles.input}
                  required
                  placeholder="3-32 chars: a-z, 0-9, _ and -"
                />
              </div>
              <div style={styles.field}>
                <label style={styles.label}>Temporary password</label>
                <input
                  type="text"
                  value={createPassword}
                  onChange={(e) => setCreatePassword(e.target.value)}
                  style={styles.input}
                  required
                  placeholder="Share this with the user to let them log in"
                />
              </div>
              <div style={styles.field}>
                <label style={styles.label}>Storage quota (GB)</label>
                <input
                  type="number"
                  value={createQuotaGB}
                  onChange={(e) => setCreateQuotaGB(e.target.value)}
                  style={styles.input}
                  min="1"
                  step="1"
                />
              </div>
              {createError && <p style={styles.errorText}>{createError}</p>}
              <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                <button
                  type="button"
                  style={styles.cancelBtn}
                  onClick={() => setShowCreateUser(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{ ...styles.submitBtn, opacity: createLoading ? 0.6 : 1 }}
                  disabled={createLoading}
                >
                  {createLoading ? 'Creating…' : 'Create user'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`
}

const styles: Record<string, React.CSSProperties> = {
  container: { padding: 32, maxWidth: 1100, margin: '0 auto' },
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 32 },
  title: { margin: 0, fontSize: 24, fontWeight: 700 },
  backBtn: { padding: '8px 16px', background: '#112030', border: '1px solid #1a3045', color: '#d4ecf7', borderRadius: 8, cursor: 'pointer', fontSize: 13 },
  statsGrid: { display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 24 },
  stat: { background: '#0c1a27', border: '1px solid #1a3045', borderRadius: 10, padding: '16px 20px' },
  statNum: { fontSize: 24, fontWeight: 700, color: '#0ea5e9' },
  statLabel: { fontSize: 12, color: '#4e7a97', marginTop: 4 },
  settingsRow: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16, padding: '12px 16px', background: '#0c1a27', border: '1px solid #1a3045', borderRadius: 8 },
  settingsLabel: { fontSize: 13, color: '#93c0d8', flex: 1 },
  toggleBtn: { padding: '4px 14px', borderRadius: 6, fontSize: 13, fontWeight: 600, cursor: 'pointer', transition: 'all 0.15s' },
  note: { background: '#1a1f1a', border: '1px solid #22c55e40', borderRadius: 8, padding: '10px 16px', fontSize: 13, color: '#22c55e', marginBottom: 24 },
  table: { width: '100%', borderCollapse: 'collapse' },
  th: { padding: '10px 12px', textAlign: 'left', fontSize: 12, color: '#4e7a97', borderBottom: '1px solid #1a3045', fontWeight: 500 },
  tr: { borderBottom: '1px solid #0c2030' },
  td: { padding: '10px 12px', fontSize: 13, color: '#93c0d8' },
  badge: { marginLeft: 6, padding: '1px 6px', background: '#0ea5e940', color: '#7dd3fc', borderRadius: 4, fontSize: 11 },
  smallBtn: { padding: '3px 8px', background: 'transparent', border: '1px solid #1a3045', color: '#4e7a97', borderRadius: 4, cursor: 'pointer', fontSize: 12, marginRight: 4 },
  input: { width: '100%', padding: '10px 12px', background: '#060d14', border: '1px solid #1a3045', borderRadius: 8, color: '#d4ecf7', fontSize: 14, outline: 'none' },
  error: { background: '#2d1a1a', border: '1px solid #ef444440', borderRadius: 8, padding: '12px 16px', marginBottom: 16, color: '#ef4444', fontSize: 13 },
  spinner: { width: 32, height: 32, border: '3px solid #1a3045', borderTop: '3px solid #0ea5e9', borderRadius: '50%', margin: '80px auto', animation: 'spin 1s linear infinite' },
  modalOverlay: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 },
  modal: { background: '#0c1a27', border: '1px solid #1a3045', borderRadius: 12, padding: 32, width: '100%', maxWidth: 440 },
  modalTitle: { margin: '0 0 6px', fontSize: 18, fontWeight: 600, color: '#d4ecf7' },
  modalSubtitle: { margin: '0 0 20px', fontSize: 13, color: '#4e7a97' },
  field: { marginBottom: 16 },
  label: { display: 'block', marginBottom: 6, fontSize: 13, color: '#4e7a97', fontWeight: 500 },
  errorText: { color: '#ef4444', fontSize: 13, margin: '8px 0' },
  cancelBtn: { flex: 1, padding: '10px', background: 'transparent', border: '1px solid #1a3045', color: '#4e7a97', borderRadius: 8, fontSize: 14, cursor: 'pointer' },
  submitBtn: { flex: 1, padding: '10px', background: '#0ea5e9', color: '#fff', border: 'none', borderRadius: 8, fontSize: 14, fontWeight: 600, cursor: 'pointer' },
}
