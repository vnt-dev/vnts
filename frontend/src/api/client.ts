import router from '@/router'
import { useAuthStore } from '@/composables/useAuth'
import type { ApiResponse } from '@/types'

const API_BASE = '/api'

export class ApiError extends Error {
  code: number

  constructor(code: number, msg: string) {
    super(msg)
    this.code = code
  }
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  body?: unknown
}

function authHeaders(): Record<string, string> {
  const { token } = useAuthStore()
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token.value) headers['Authorization'] = `Bearer ${token.value}`
  return headers
}

async function handle401(): Promise<void> {
  useAuthStore().logout()
  if (router.currentRoute.value.name !== 'login') {
    await router.push({ name: 'login' })
  }
}

async function doFetch<T>(path: string, options: RequestOptions): Promise<T | null> {
  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: options.method ?? 'GET',
      headers: authHeaders(),
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    })
  } catch {
    throw new ApiError(0, '网络请求失败，请确认服务已启动')
  }

  const json = (await res.json().catch(() => null)) as ApiResponse<unknown> | null
  if (res.status === 401 || json?.code === 401) {
    await handle401()
    return null
  }
  if (!json || json.code !== 200) {
    throw new ApiError(json?.code ?? res.status, json?.msg ?? '请求失败')
  }
  return (json.data ?? true) as T
}

/** 常规请求：失败抛出 ApiError（401 会登出并跳转登录页） */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const data = await doFetch<T>(path, options)
  if (data === null) throw new ApiError(401, '登录已过期，请重新登录')
  return data
}

/** 静默请求（轮询用）：失败返回 null，不抛错 */
export async function fetchSilent<T>(path: string): Promise<T | null> {
  try {
    return await doFetch<T>(path, {})
  } catch {
    return null
  }
}

export async function downloadFile(path: string, filename: string): Promise<void> {
  const res = await fetch(`${API_BASE}${path}`, { headers: authHeaders() })
  if (res.status === 401) {
    await handle401()
    throw new ApiError(401, '登录已过期，请重新登录')
  }
  if (!res.ok) {
    const json = (await res.json().catch(() => null)) as ApiResponse<unknown> | null
    throw new ApiError(json?.code ?? res.status, json?.msg ?? '下载失败')
  }
  const url = URL.createObjectURL(await res.blob())
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}
