import { useState } from 'react'
import { useForm, type Resolver } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2, Plus, Check, X } from 'lucide-react'
import { useAppSelector } from '@/store'
import { selectIsLoggedIn, selectIsAdmin } from '@/store/authSlice'
import {
  useAdminUsers, useAdminStats, useAdminSettings,
  useCreateUser, useUpdateUser, useDeleteUser, useUpdateAdminSettings,
} from '@/api/hooks/useAdmin'
import { formatBytes } from '@/lib/format'
import { Navigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Card, CardContent } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'

const createUserSchema = z.object({
  email: z.string().email('Invalid email'),
  username: z
    .string()
    .min(3, 'At least 3 characters')
    .max(32)
    .regex(/^[a-z0-9_-]+$/, 'Lowercase letters, numbers, _ and - only'),
  tempPassword: z.string().min(1, 'Required'),
  quotaGB: z.coerce.number().min(1, 'At least 1 GB'),
})
type CreateUserForm = z.infer<typeof createUserSchema>

export default function Admin() {
  const isLoggedIn = useAppSelector(selectIsLoggedIn)
  const isAdmin = useAppSelector(selectIsAdmin)

  if (!isLoggedIn) return <Navigate to="/login" replace />
  if (!isAdmin) return <Navigate to="/drive" replace />

  return <AdminContent />
}

function AdminContent() {
  const { data: users, isLoading: usersLoading } = useAdminUsers()
  const { data: stats } = useAdminStats()
  const { data: settings } = useAdminSettings()
  const createUser = useCreateUser()
  const updateUser = useUpdateUser()
  const deleteUser = useDeleteUser()
  const updateSettings = useUpdateAdminSettings()

  const [createOpen, setCreateOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; email: string } | null>(null)
  const [editQuota, setEditQuota] = useState<{ userId: string; gb: string } | null>(null)

  const form = useForm<CreateUserForm>({
    resolver: zodResolver(createUserSchema) as Resolver<CreateUserForm>,
    defaultValues: { email: '', username: '', tempPassword: '', quotaGB: 10 },
  })

  async function onCreateUser(data: CreateUserForm) {
    await createUser.mutateAsync({
      email: data.email,
      username: data.username,
      tempPassword: data.tempPassword,
      storageQuotaBytes: data.quotaGB * 1024 * 1024 * 1024,
    })
    form.reset()
    setCreateOpen(false)
  }

  async function handleSaveQuota(userId: string, gb: string) {
    const n = parseFloat(gb)
    if (isNaN(n) || n <= 0) return
    await updateUser.mutateAsync({ id: userId, body: { storageQuotaBytes: n * 1024 * 1024 * 1024 } })
    setEditQuota(null)
  }

  const statItems = stats
    ? [
        { label: 'Total users', value: stats.totalUsers },
        { label: 'Active users', value: stats.activeUsers },
        { label: 'Total files', value: stats.totalFiles },
        { label: 'Collections', value: stats.totalCollections },
        { label: 'Storage used', value: formatBytes(stats.totalStorageUsedBytes) },
      ]
    : []

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Admin Panel</h1>
        <Button size="sm" onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Create user
        </Button>
      </div>

      {/* Stats */}
      {statItems.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {statItems.map((s) => (
            <Card key={s.label}>
              <CardContent className="pt-4 pb-4">
                <div className="text-2xl font-bold text-primary">{s.value}</div>
                <div className="text-xs text-muted-foreground mt-1">{s.label}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Registration toggle */}
      <div className="flex items-center justify-between p-3 bg-card border border-border rounded-lg">
        <span className="text-sm">Public registration</span>
        <Button
          variant="outline"
          size="sm"
          className={settings?.registrationEnabled
            ? 'border-green-500/50 text-green-400 hover:bg-green-500/10'
            : 'border-destructive/50 text-destructive hover:bg-destructive/10'}
          onClick={() => updateSettings.mutate({ registrationEnabled: !settings?.registrationEnabled })}
          disabled={updateSettings.isPending || !settings}
        >
          {settings?.registrationEnabled ? 'Enabled' : 'Disabled'}
        </Button>
      </div>

      <Alert className="border-green-500/30 text-green-400 bg-green-500/5">
        <AlertDescription className="text-xs">
          File names and contents are encrypted. Admins cannot see user data.
        </AlertDescription>
      </Alert>

      {/* Users table */}
      {usersLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Email</TableHead>
              <TableHead>Username</TableHead>
              <TableHead>Quota</TableHead>
              <TableHead>Used</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>TOTP</TableHead>
              <TableHead>Joined</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {users?.map((user) => (
              <TableRow key={user.id}>
                <TableCell>
                  <div className="flex items-center gap-2">
                    {user.email}
                    {user.isAdmin && <Badge variant="secondary" className="text-xs">admin</Badge>}
                  </div>
                </TableCell>
                <TableCell className="text-muted-foreground">@{user.username}</TableCell>
                <TableCell>
                  {editQuota?.userId === user.id ? (
                    <div className="flex items-center gap-1">
                      <Input
                        type="number"
                        value={editQuota.gb}
                        onChange={(e) => setEditQuota({ ...editQuota, gb: e.target.value })}
                        className="h-7 w-16 text-xs"
                        autoFocus
                      />
                      <span className="text-xs text-muted-foreground">GB</span>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => handleSaveQuota(user.id, editQuota.gb)}
                      >
                        <Check className="h-3.5 w-3.5 text-green-400" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => setEditQuota(null)}
                      >
                        <X className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  ) : (
                    <button
                      className="text-sm underline decoration-dotted text-muted-foreground hover:text-foreground"
                      onClick={() => setEditQuota({ userId: user.id, gb: String(user.storageQuotaBytes / 1024 / 1024 / 1024) })}
                    >
                      {formatBytes(user.storageQuotaBytes)}
                    </button>
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground">{formatBytes(user.storageUsedBytes)}</TableCell>
                <TableCell>
                  <Badge
                    variant="outline"
                    className={user.isActive
                      ? 'border-green-500/50 text-green-400'
                      : 'border-destructive/50 text-destructive'}
                  >
                    {user.isActive ? 'Active' : 'Disabled'}
                  </Badge>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {user.totpEnabled ? <Check className="h-4 w-4 text-green-400" /> : '—'}
                </TableCell>
                <TableCell className="text-muted-foreground text-xs">
                  {new Date(user.createdAt).toLocaleDateString()}
                </TableCell>
                <TableCell>
                  <div className="flex gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 text-xs"
                      onClick={() => updateUser.mutate({ id: user.id, body: { isActive: !user.isActive } })}
                    >
                      {user.isActive ? 'Disable' : 'Enable'}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 text-xs text-destructive hover:text-destructive"
                      onClick={() => setDeleteTarget({ id: user.id, email: user.email })}
                    >
                      Delete
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {/* Create user dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create user</DialogTitle>
            <DialogDescription>
              The user will set their own password and recovery phrase on first login.
            </DialogDescription>
          </DialogHeader>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onCreateUser)} className="space-y-4">
              <FormField control={form.control} name="email" render={({ field }) => (
                <FormItem>
                  <FormLabel>Email</FormLabel>
                  <FormControl><Input type="email" autoComplete="email" autoFocus {...field} /></FormControl>
                  <FormMessage />
                </FormItem>
              )} />
              <FormField control={form.control} name="username" render={({ field }) => (
                <FormItem>
                  <FormLabel>Username</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="3-32 chars: a-z, 0-9, _ and -"
                      {...field}
                      onChange={(e) => field.onChange(e.target.value.toLowerCase())}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )} />
              <FormField control={form.control} name="tempPassword" render={({ field }) => (
                <FormItem>
                  <FormLabel>Temporary password</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="Share this with the user"
                      autoComplete="off"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )} />
              <FormField control={form.control} name="quotaGB" render={({ field }) => (
                <FormItem>
                  <FormLabel>Storage quota (GB)</FormLabel>
                  <FormControl><Input type="number" min="1" step="1" {...field} /></FormControl>
                  <FormMessage />
                </FormItem>
              )} />
              <DialogFooter>
                <Button variant="outline" type="button" onClick={() => { form.reset(); setCreateOpen(false) }}>
                  Cancel
                </Button>
                <Button type="submit" disabled={form.formState.isSubmitting}>
                  {form.formState.isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Create user
                </Button>
              </DialogFooter>
            </form>
          </Form>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <AlertDialog open={deleteTarget !== null} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {deleteTarget?.email}?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently deletes the account and all associated data. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => { if (deleteTarget) deleteUser.mutate(deleteTarget.id); setDeleteTarget(null) }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
