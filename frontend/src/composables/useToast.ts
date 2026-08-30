import { reactive } from 'vue'

export type ToastType = 'success' | 'error' | 'info'

export interface ToastItem {
  id: number
  type: ToastType
  message: string
}

const toasts = reactive<ToastItem[]>([])
let seq = 0

export function useToast() {
  function dismiss(id: number) {
    const index = toasts.findIndex((t) => t.id === id)
    if (index >= 0) toasts.splice(index, 1)
  }

  function show(message: string, type: ToastType = 'info', duration = 3000) {
    const id = ++seq
    toasts.push({ id, type, message })
    if (duration > 0) {
      setTimeout(() => dismiss(id), duration)
    }
  }

  return {
    toasts,
    show,
    dismiss,
    success: (message: string) => show(message, 'success'),
    error: (message: string) => show(message, 'error'),
    info: (message: string) => show(message, 'info'),
  }
}