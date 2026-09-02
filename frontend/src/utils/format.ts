const KIB = 1024

export function formatBytes(bytes: number | null | undefined): string {
  if (!bytes) return '0 B'
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(KIB)), sizes.length - 1)
  return `${parseFloat((bytes / Math.pow(KIB, i)).toFixed(2))} ${sizes[i]}`
}

export function formatSpeed(bps: number | null | undefined): string {
  if (!bps) return '0 B/s'
  const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s']
  const i = Math.min(Math.floor(Math.log(bps) / Math.log(KIB)), sizes.length - 1)
  return `${parseFloat((bps / Math.pow(KIB, i)).toFixed(2))} ${sizes[i]}`
}

export function formatDuration(seconds: number | null | undefined): string {
  if (!seconds || seconds <= 0) return '-'
  if (seconds >= 86400) {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    return hours > 0 ? `${days}天${hours}小时` : `${days}天`
  }
  if (seconds >= 3600) {
    const hours = Math.floor(seconds / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    return mins > 0 ? `${hours}小时${mins}分钟` : `${hours}小时`
  }
  if (seconds >= 60) return `${Math.floor(seconds / 60)}分钟`
  return `${seconds}秒`
}

export const SOURCE_LABELS: Record<string, string> = {
  Config: '配置初始化',
  Manual: '手动创建',
  DeviceRegister: '设备注册',
}

export function formatSource(source?: string): string {
  return (source && SOURCE_LABELS[source]) || source || '未知'
}

export function sourceBadgeClass(source?: string): string {
  switch (source) {
    case 'Config':
      return 'bg-purple-50 text-purple-700 ring-purple-200 dark:bg-purple-500/10 dark:text-purple-400 dark:ring-purple-500/30'
    case 'Manual':
      return 'bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:ring-emerald-500/30'
    case 'DeviceRegister':
      return 'bg-amber-50 text-amber-700 ring-amber-200 dark:bg-amber-500/10 dark:text-amber-400 dark:ring-amber-500/30'
    default:
      return 'bg-slate-100 text-slate-600 ring-slate-200 dark:bg-slate-700/60 dark:text-slate-400 dark:ring-slate-600/60'
  }
}

export type LatencyLevel = 'good' | 'mid' | 'bad' | 'none'

export function latencyLevel(ms: number | null | undefined): LatencyLevel {
  if (ms === null || ms === undefined) return 'none'
  if (ms < 50) return 'good'
  if (ms < 100) return 'mid'
  return 'bad'
}

export function latencyTextClass(level: LatencyLevel): string {
  switch (level) {
    case 'good':
      return 'text-emerald-600 dark:text-emerald-400'
    case 'mid':
      return 'text-amber-600 dark:text-amber-400'
    case 'bad':
      return 'text-red-600 dark:text-red-400'
    default:
      return 'text-slate-400 dark:text-slate-500'
  }
}