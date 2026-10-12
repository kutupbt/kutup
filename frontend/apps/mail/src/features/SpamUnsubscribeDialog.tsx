import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { closeSpamAsk, useSpamAsk } from './spamUnsubscribe'

/** Proton's GlobalUnsubscribeModal: moving list mail to Spam, with unsubscribing or without, the choice remembered if asked. */
export function SpamUnsubscribeDialog() {
  const { t } = useTranslation()
  const ask = useSpamAsk()
  const [remember, setRemember] = useState(false)
  if (!ask) return null
  const choose = (unsubscribe: boolean) => {
    const keep = remember
    setRemember(false)
    closeSpamAsk()
    ask.onChoice(unsubscribe, keep)
  }
  const close = () => {
    setRemember(false)
    closeSpamAsk()
  }
  return (
    <Dialog open onOpenChange={(open) => !open && close()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('spamUnsubscribe.title')}</DialogTitle>
          <DialogDescription>{t(ask.conversations ? 'spamUnsubscribe.bodyConversations' : 'spamUnsubscribe.bodyMessages', { count: ask.count })}</DialogDescription>
        </DialogHeader>
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={remember} onCheckedChange={(on) => setRemember(on === true)} />
          {t('spamUnsubscribe.remember')}
        </label>
        <DialogFooter className="gap-2 sm:flex-wrap">
          <Button variant="outline" onClick={close}>
            {t('common.cancel')}
          </Button>
          <Button variant="outline" onClick={() => choose(false)}>
            {t('spamUnsubscribe.justSpam')}
          </Button>
          <Button onClick={() => choose(true)}>{t('spamUnsubscribe.andUnsubscribe')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
