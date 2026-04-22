import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2, Shield, KeyRound } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useAppSelector, useAppDispatch } from '@/store'
import { updateTotpEnabled } from '@/store/authSlice'
import api from '@/api/client'
import { formatBytes } from '@/lib/format'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { Separator } from '@/components/ui/separator'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { toast } from 'sonner'

const totpVerifySchema = z.object({
  code: z.string().length(6, 'Code must be 6 digits').regex(/^\d+$/, 'Digits only'),
})
type TotpVerifyForm = z.infer<typeof totpVerifySchema>

export default function Settings() {
  const dispatch = useAppDispatch()
  const auth = useAppSelector((s) => s.auth)

  const [totpSetup, setTotpSetup] = useState<{ secret: string; qrUri: string } | null>(null)
  const [totpDialogOpen, setTotpDialogOpen] = useState(false)
  const [setupLoading, setSetupLoading] = useState(false)

  const quotaPercent =
    auth.storageQuotaBytes > 0
      ? Math.min(Math.round((auth.storageUsedBytes / auth.storageQuotaBytes) * 100), 100)
      : 0

  const totpForm = useForm<TotpVerifyForm>({ resolver: zodResolver(totpVerifySchema) })

  async function startTOTPSetup() {
    setSetupLoading(true)
    try {
      const res = await api.post('/user/2fa/setup')
      setTotpSetup(res.data)
      setTotpDialogOpen(true)
    } catch (err: any) {
      toast.error(err.response?.data?.error ?? 'Failed to start TOTP setup')
    } finally {
      setSetupLoading(false)
    }
  }

  async function onVerifyTOTP({ code }: TotpVerifyForm) {
    try {
      await api.post('/user/2fa/verify', { code })
      dispatch(updateTotpEnabled(true))
      setTotpDialogOpen(false)
      setTotpSetup(null)
      totpForm.reset()
      toast.success('Two-factor authentication enabled')
    } catch (err: any) {
      totpForm.setError('code', { message: err.response?.data?.error ?? 'Invalid code' })
    }
  }

  async function disableTOTP() {
    try {
      await api.delete('/user/2fa')
      dispatch(updateTotpEnabled(false))
      toast.success('Two-factor authentication disabled')
    } catch (err: any) {
      toast.error(err.response?.data?.error ?? 'Failed to disable TOTP')
    }
  }

  return (
    <div className="max-w-2xl mx-auto p-6 space-y-4">
      <h1 className="text-2xl font-bold">Settings</h1>

      {/* Account info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Account</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex justify-between items-center py-1">
            <span className="text-sm text-muted-foreground">Email</span>
            <span className="text-sm">{auth.email}</span>
          </div>
          <Separator />
          <div className="flex justify-between items-center py-1">
            <span className="text-sm text-muted-foreground">Username</span>
            <span className="text-sm">@{auth.username}</span>
          </div>
          <Separator />
          <div className="space-y-2 py-1">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Storage</span>
              <span>{formatBytes(auth.storageUsedBytes)} / {formatBytes(auth.storageQuotaBytes)}</span>
            </div>
            <Progress value={quotaPercent} className="h-1.5" />
          </div>
        </CardContent>
      </Card>

      {/* TOTP */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Two-Factor Authentication
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {auth.totpEnabled ? (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="border-green-500/50 text-green-400">Enabled</Badge>
                <span className="text-sm text-muted-foreground">TOTP is active on this account</span>
              </div>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button variant="destructive" size="sm">Disable TOTP</Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Disable two-factor authentication?</AlertDialogTitle>
                    <AlertDialogDescription>
                      This reduces your account security. You will no longer be asked for a code when signing in.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                      className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                      onClick={disableTOTP}
                    >
                      Disable
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                Add an extra layer of security with an authenticator app.
              </p>
              <Button size="sm" onClick={startTOTPSetup} disabled={setupLoading}>
                {setupLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Set up TOTP
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Encryption info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <KeyRound className="h-4 w-4" />
            Encryption
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            All files are encrypted client-side using XChaCha20-Poly1305. Your master key and private
            key are derived from your password using Argon2id and are never sent to the server.
            The server stores only ciphertext it cannot decrypt.
          </p>
          <p>
            To change your password, use the{' '}
            <Link to="/recover" className="text-primary hover:underline">account recovery</Link>{' '}
            flow with your 24-word mnemonic.
          </p>
        </CardContent>
      </Card>

      {/* TOTP setup dialog */}
      <Dialog open={totpDialogOpen} onOpenChange={setTotpDialogOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>Set up two-factor authentication</DialogTitle>
          </DialogHeader>
          {totpSetup && (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
              </p>
              <div className="flex justify-center bg-white rounded-lg p-3">
                <QRCodeSVG value={totpSetup.qrUri} size={160} />
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1">Manual entry key:</p>
                <code className="block bg-muted px-3 py-2 rounded text-xs font-mono tracking-widest text-primary">
                  {totpSetup.secret}
                </code>
              </div>
              <Form {...totpForm}>
                <form onSubmit={totpForm.handleSubmit(onVerifyTOTP)} className="space-y-3">
                  <FormField
                    control={totpForm.control}
                    name="code"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Enter the 6-digit code to confirm</FormLabel>
                        <FormControl>
                          <Input
                            type="text"
                            inputMode="numeric"
                            pattern="[0-9]{6}"
                            maxLength={6}
                            className="text-center text-xl tracking-widest"
                            placeholder="000000"
                            autoFocus
                            autoComplete="one-time-code"
                            {...field}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <DialogFooter>
                    <Button variant="outline" type="button" onClick={() => setTotpDialogOpen(false)}>
                      Cancel
                    </Button>
                    <Button type="submit" disabled={totpForm.formState.isSubmitting}>
                      {totpForm.formState.isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                      Enable TOTP
                    </Button>
                  </DialogFooter>
                </form>
              </Form>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
