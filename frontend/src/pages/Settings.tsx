import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2, Shield, KeyRound, ArrowLeft, Globe, Check, ChevronDown, Smartphone } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useAppSelector, useAppDispatch } from '@/store'
import { updateTotpEnabled, setColor } from '@/store/authSlice'
import { CURSOR_COLORS_20 } from '@/collab/identity'
import { broadcastColor } from '@/lib/sessionSync'
import api from '@/api/client'
import { listDevices, revokeDevice, type DeviceRow } from '@/api/collab'
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

const totpVerifySchema = z.object({
  code: z.string().length(6, 'Code must be 6 digits').regex(/^\d+$/, 'Digits only'),
})
type TotpVerifyForm = z.infer<typeof totpVerifySchema>

const LANGUAGES = [
  { code: 'en', label: 'English' },
  { code: 'tr', label: 'Türkçe' },
]

function DevicesSection() {
  const { t } = useTranslation()
  const [devs, setDevs] = useState<DeviceRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = async () => {
    setLoading(true)
    setError(null)
    try {
      const list = await listDevices()
      setDevs(list)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'load failed')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    refresh()
  }, [])

  const onRevoke = async (id: number) => {
    try {
      await revokeDevice(id)
      setDevs((arr) => arr.map((x) => (x.deviceId === id ? { ...x, isActive: false } : x)))
      toast.success(t('settings.devices.revokedToast'))
    } catch (e) {
      toast.error(t('settings.devices.revokeFailed', { error: e instanceof Error ? e.message : String(e) }))
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Smartphone className="h-4 w-4" />
          {t('settings.devices.title')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">
          {t('settings.devices.desc')}
        </p>
        {loading && <div className="text-sm text-muted-foreground">{t('common.loading')}</div>}
        {error && <div className="text-sm text-destructive">{t('settings.devices.errorPrefix')} {error}</div>}
        {!loading && !error && devs.length === 0 && (
          <div className="text-sm text-muted-foreground">{t('settings.devices.empty')}</div>
        )}
        {devs.length > 0 && (
          <ul className="divide-y rounded border">
            {devs.map((d) => {
              const label = d.label || t('settings.devices.fallbackLabel', { id: d.deviceId })
              return (
                <li key={d.deviceId} className="flex items-center justify-between gap-2 p-3">
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm">{label}</div>
                    <div className="text-xs text-muted-foreground">
                      {d.isActive ? t('settings.devices.active') : t('settings.devices.revoked')} ·{' '}
                      {t('settings.devices.createdAt', { when: new Date(d.createdAt).toLocaleString() })}
                      {d.lastSeenAt && ` · ${t('settings.devices.lastSeenAt', { when: new Date(d.lastSeenAt).toLocaleString() })}`}
                    </div>
                  </div>
                  {d.isActive && (
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button variant="outline" size="sm">
                          {t('settings.devices.revoke')}
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>{t('settings.devices.revokeTitle')}</AlertDialogTitle>
                          <AlertDialogDescription>
                            {t('settings.devices.revokeDesc', { label })}
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                          <AlertDialogAction
                            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                            onClick={() => onRevoke(d.deviceId)}
                          >
                            {t('settings.devices.revoke')}
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

export default function Settings() {
  const { t, i18n } = useTranslation()
  const dispatch = useAppDispatch()
  const lang = i18n.language.startsWith('tr') ? 'tr' : 'en'
  const currentLang = LANGUAGES.find((l) => l.code === lang)
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
      toast.error(err.response?.data?.error ?? t('settings.totp.setupFailed'))
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
      toast.success(t('settings.totp.enabledToast'))
    } catch (err: any) {
      totpForm.setError('code', { message: err.response?.data?.error ?? 'Invalid code' })
    }
  }

  async function disableTOTP() {
    try {
      await api.delete('/user/2fa')
      dispatch(updateTotpEnabled(false))
      toast.success(t('settings.totp.disabledToast'))
    } catch (err: any) {
      toast.error(err.response?.data?.error ?? t('settings.totp.disableFailed'))
    }
  }

  async function updatePresenceColor(hex: string | null) {
    const previous = auth.color
    dispatch(setColor(hex))
    broadcastColor(hex)
    try {
      await api.patch('/user/me', { color: hex ?? '' })
    } catch (err: any) {
      dispatch(setColor(previous))
      broadcastColor(previous)
      toast.error(err.response?.data?.error ?? t('settings.account.presenceColorFailed'))
    }
  }

  return (
    <div className="max-w-2xl mx-auto p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" asChild>
          <Link to="/drive"><ArrowLeft className="h-4 w-4 mr-1" />{t('common.drive')}</Link>
        </Button>
        <h1 className="text-2xl font-bold">{t('settings.title')}</h1>
      </div>

      {/* Account info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('settings.account.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex justify-between items-center py-1">
            <span className="text-sm text-muted-foreground">{t('settings.account.email')}</span>
            <span className="text-sm">{auth.email}</span>
          </div>
          <Separator />
          <div className="flex justify-between items-center py-1">
            <span className="text-sm text-muted-foreground">{t('settings.account.username')}</span>
            <span className="text-sm">@{auth.username}</span>
          </div>
          <Separator />
          <div className="space-y-2 py-1">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">{t('settings.account.storage')}</span>
              <span>{formatBytes(auth.storageUsedBytes)} / {formatBytes(auth.storageQuotaBytes)}</span>
            </div>
            <Progress value={quotaPercent} className="h-1.5" />
          </div>
          <Separator />
          <div className="space-y-2 py-1">
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">{t('settings.account.presenceColor')}</span>
              {auth.color && (
                <Button variant="ghost" size="sm" onClick={() => updatePresenceColor(null)}>
                  {t('settings.account.presenceColorClear')}
                </Button>
              )}
            </div>
            <p className="text-xs text-muted-foreground">{t('settings.account.presenceColorDesc')}</p>
            <div className="grid grid-cols-10 gap-1.5">
              {CURSOR_COLORS_20.map((hex) => (
                <button
                  key={hex}
                  type="button"
                  onClick={() => updatePresenceColor(hex)}
                  className={`h-7 w-7 rounded-full border-2 ${auth.color === hex ? 'border-foreground' : 'border-transparent'} hover:scale-110 transition-transform`}
                  style={{ background: hex }}
                  aria-label={hex}
                  title={hex}
                />
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* TOTP */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="h-4 w-4" />
            {t('settings.totp.title')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {auth.totpEnabled ? (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="border-green-500/50 text-green-400">{t('settings.totp.enabled')}</Badge>
                <span className="text-sm text-muted-foreground">{t('settings.totp.active')}</span>
              </div>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button variant="destructive" size="sm">{t('settings.totp.disable')}</Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>{t('settings.totp.disableTitle')}</AlertDialogTitle>
                    <AlertDialogDescription>
                      {t('settings.totp.disableDesc')}
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                    <AlertDialogAction
                      className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                      onClick={disableTOTP}
                    >
                      {t('settings.totp.disableConfirm')}
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {t('settings.totp.addSecurity')}
              </p>
              <Button size="sm" onClick={startTOTPSetup} disabled={setupLoading}>
                {setupLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {t('settings.totp.setUp')}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Devices */}
      <DevicesSection />

      {/* Language */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Globe className="h-4 w-4" />
            {t('settings.language.title')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">{t('settings.language.desc')}</p>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" className="gap-2">
                  <Globe className="h-3.5 w-3.5" />
                  {currentLang?.label}
                  <ChevronDown className="h-3.5 w-3.5" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {LANGUAGES.map((l) => (
                  <DropdownMenuItem
                    key={l.code}
                    onClick={() => i18n.changeLanguage(l.code)}
                    className="gap-2"
                  >
                    <Check className={`h-3.5 w-3.5 ${lang === l.code ? 'opacity-100' : 'opacity-0'}`} />
                    {l.label}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </CardContent>
      </Card>

      {/* Encryption info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <KeyRound className="h-4 w-4" />
            {t('settings.encryption.title')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>{t('settings.encryption.desc1')}</p>
          <p>
            {t('settings.encryption.desc2')}{' '}
            <Link to="/recover" className="text-primary hover:underline">{t('settings.encryption.recoveryLink')}</Link>{' '}
            {t('settings.encryption.desc2end')}
          </p>
        </CardContent>
      </Card>

      {/* TOTP setup dialog */}
      <Dialog open={totpDialogOpen} onOpenChange={setTotpDialogOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>{t('settings.totp.setupTitle')}</DialogTitle>
          </DialogHeader>
          {totpSetup && (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                {t('settings.totp.scanQr')}
              </p>
              <div className="flex justify-center bg-white rounded-lg p-3">
                <QRCodeSVG value={totpSetup.qrUri} size={160} />
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1">{t('settings.totp.manualKey')}</p>
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
                        <FormLabel>{t('settings.totp.confirmCode')}</FormLabel>
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
                      {t('common.cancel')}
                    </Button>
                    <Button type="submit" disabled={totpForm.formState.isSubmitting}>
                      {totpForm.formState.isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                      {t('settings.totp.enableButton')}
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
