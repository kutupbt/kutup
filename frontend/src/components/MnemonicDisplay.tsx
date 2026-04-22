import { useState, useCallback } from 'react'
import { Copy, Check, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'

interface Props {
  mnemonic: string
}

export default function MnemonicDisplay({ mnemonic }: Props) {
  const [copied, setCopied] = useState(false)
  const words = mnemonic.split(' ')

  const handleCopy = useCallback(() => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(mnemonic).then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      })
    } else {
      const ta = document.createElement('textarea')
      ta.value = mnemonic
      ta.style.cssText = 'position:fixed;opacity:0'
      document.body.appendChild(ta)
      ta.focus()
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }, [mnemonic])

  const handleDownload = useCallback(() => {
    const blob = new Blob([mnemonic], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'kutup-recovery-phrase.txt'
    a.click()
    URL.revokeObjectURL(url)
  }, [mnemonic])

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-4 gap-2 bg-muted/50 rounded-lg p-4">
        {words.map((word, i) => (
          <div
            key={i}
            className="bg-card rounded-md px-2 py-1.5 text-sm font-mono"
          >
            <span className="text-xs text-muted-foreground mr-1">{i + 1}.</span>
            {word}
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" className="flex-1" onClick={handleCopy}>
          {copied ? (
            <><Check className="h-4 w-4 mr-2" />Copied!</>
          ) : (
            <><Copy className="h-4 w-4 mr-2" />Copy</>
          )}
        </Button>
        <Button variant="outline" size="sm" className="flex-1" onClick={handleDownload}>
          <Download className="h-4 w-4 mr-2" />
          Download
        </Button>
      </div>
    </div>
  )
}
