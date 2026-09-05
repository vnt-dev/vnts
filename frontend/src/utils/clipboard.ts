function copyWithSelection(value: string) {
  if (!document.body) return false

  const textarea = document.createElement('textarea')
  const activeElement = document.activeElement instanceof HTMLElement ? document.activeElement : null

  textarea.value = value
  textarea.readOnly = true
  textarea.style.position = 'fixed'
  textarea.style.left = '-9999px'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  textarea.setSelectionRange(0, value.length)

  try {
    return document.execCommand('copy')
  } finally {
    textarea.remove()
    activeElement?.focus()
  }
}

export async function copyText(value: string) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value)
      return
    } catch {
      // Clipboard API may be blocked by browser permissions; use the legacy
      // synchronous path while this call still has the user's click gesture.
    }
  }

  if (!copyWithSelection(value)) {
    throw new Error('Clipboard is unavailable')
  }
}
