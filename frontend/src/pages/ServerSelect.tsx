// Nextcloud-style "which server do I sign into?" prompt.
//
// Only used by the Tauri desktop / mobile shells. On the web the backend is
// same-origin and there's no server-pick step.
//
// Flow: input → normalize (https prepend, http-on-localhost-only, trailing
// slash strip) → probe `${url}/api/health` with a 5 s timeout → on a valid
// kutup response, persist via the Tauri Store plugin and navigate to /login.
//
// "Allow insecure connection" checkbox: when ticked, the probe and all
// subsequent HTTP go through tauri-plugin-http with TLS cert/hostname
// verification disabled — for self-signed servers or connecting by IP. The
// flag is persisted alongside the URL. (Large-file uploads still use the
// webview's XHR and so still need a valid cert; see lib/httpClient.)

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'

import {
  normalizeServerUrl,
  setServerUrl,
  setServerInsecure,
} from '@/lib/serverConfig'
import { invalidateApiBase } from '@/lib/apiBase'
import { httpFetch } from '@/lib/httpClient'
import { KutupLogo } from '@/components/KutupLogo'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const schema = z.object({
  url: z.string().min(1),
})
type FormShape = z.infer<typeof schema>

async function probeHealth(
  origin: string,
  insecure: boolean,
  timeoutMs: number,
): Promise<{ ok: boolean; isKutup: boolean }> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs)
  try {
    // forceInsecure = the checkbox value: the persisted flag isn't cached yet
    // at this point in the flow.
    const r = await httpFetch(
      `${origin}/api/health`,
      { signal: controller.signal },
      insecure,
    )
    if (!r.ok) return { ok: false, isKutup: false }
    const body = (await r.json()) as { name?: string }
    return { ok: true, isKutup: body?.name === 'kutup' }
  } catch {
    return { ok: false, isKutup: false }
  } finally {
    clearTimeout(timeoutId)
  }
}

export default function ServerSelect() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [error, setError] = useState<string>('')
  const [checking, setChecking] = useState(false)
  const [insecure, setInsecure] = useState(false)

  const form = useForm<FormShape>({
    resolver: zodResolver(schema),
    defaultValues: { url: '' },
  })

  async function onSubmit({ url }: FormShape) {
    setError('')
    const norm = normalizeServerUrl(url)
    if (!norm.ok) {
      const key =
        norm.error === 'empty'
          ? 'auth.serverSelect.errorEmpty'
          : norm.error === 'insecure-http'
            ? 'auth.serverSelect.errorInsecureHttp'
            : 'auth.serverSelect.errorInvalid'
      setError(t(key))
      return
    }

    setChecking(true)
    const probe = await probeHealth(norm.url, insecure, 5000)
    setChecking(false)

    if (!probe.ok) {
      setError(t('auth.serverSelect.errorUnreachable'))
      return
    }
    if (!probe.isKutup) {
      setError(t('auth.serverSelect.errorNotKutup'))
      return
    }

    await setServerUrl(norm.url)
    await setServerInsecure(insecure)
    invalidateApiBase() // next API call re-resolves with the new origin + flag
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="flex items-center gap-2.5 justify-center mb-2">
            <KutupLogo size={34} />
            <span className="text-3xl font-bold text-primary tracking-tight">
              Kutup
            </span>
          </div>
          <CardTitle className="text-center">
            {t('auth.serverSelect.title')}
          </CardTitle>
          <p className="text-sm text-muted-foreground text-center mt-1">
            {t('auth.serverSelect.subtitle')}
          </p>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form
              onSubmit={form.handleSubmit(onSubmit)}
              className="space-y-4"
              noValidate
            >
              <FormField
                control={form.control}
                name="url"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('auth.serverSelect.url')}</FormLabel>
                    <FormControl>
                      <Input
                        type="text"
                        inputMode="url"
                        autoComplete="url"
                        autoFocus
                        spellCheck={false}
                        placeholder={t('auth.serverSelect.urlPlaceholder')}
                        disabled={checking}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <label className="flex items-start gap-2 text-sm">
                <Checkbox
                  checked={insecure}
                  onCheckedChange={(v) => setInsecure(v === true)}
                  disabled={checking}
                  className="mt-0.5"
                />
                <span>
                  <span className="font-medium">
                    {t('auth.serverSelect.insecure')}
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    {t('auth.serverSelect.insecureHint')}
                  </span>
                </span>
              </label>
              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              <Button type="submit" className="w-full" disabled={checking}>
                {checking && (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                )}
                {checking
                  ? t('auth.serverSelect.checking')
                  : t('auth.serverSelect.continue')}
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  )
}
