import { computed, onUnmounted, reactive, ref } from 'vue'
import { deviceApi } from '@/api/modules'
import type { DeviceInfo } from '@/types'

/** 每个 IP 保留的历史采样点数 */
const HISTORY_SIZE = 60
export { HISTORY_SIZE as SPEED_HISTORY_SIZE }
/** 轮询间隔（毫秒） */
const POLL_INTERVAL = 3000

interface TrafficPoint {
  tx: number
  rx: number
}

export interface SpeedHistory {
  tx: number[]
  rx: number[]
}

export interface DeviceGroup {
  /** 分组键：IP 或 no-ip-<device_id>，用于展开/图表 */
  key: string
  ip: string | null
  devices: DeviceInfo[]
  hasOnline: boolean
  hasRemote: boolean
  canDelete: boolean
  bestLatency: number | null
  totalTxBytes: number
  totalRxBytes: number
  totalTxSpeed: number
  totalRxSpeed: number
}

/**
 * 设备列表监控：3s 静默轮询、前后两次流量差分计算瞬时网速、
 * 按 IP 累计速度历史（供 canvas 图表绘制）。
 */
export function useDeviceMonitor() {
  const devices = ref<DeviceInfo[]>([])
  const loading = ref(false)
  const search = ref('')
  /** group.key -> 是否展开来源明细 */
  const groupExpanded = reactive<Record<string, boolean>>({})
  /** group.key -> 是否展开速度历史图表 */
  const chartExpanded = reactive<Record<string, boolean>>({})

  let currentCode = ''
  let lastTraffic = new Map<string, TrafficPoint>()
  let lastFetchTime = 0
  const speedHistory = new Map<string, SpeedHistory>()
  const EMPTY_HISTORY: SpeedHistory = { tx: [], rx: [] }
  let timer: ReturnType<typeof setInterval> | null = null

  function resetState() {
    lastTraffic = new Map()
    lastFetchTime = 0
    speedHistory.clear()
    for (const key of Object.keys(groupExpanded)) delete groupExpanded[key]
    for (const key of Object.keys(chartExpanded)) delete chartExpanded[key]
  }

  function start() {
    stop()
    timer = setInterval(() => {
      void poll()
    }, POLL_INTERVAL)
  }

  function stop() {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
  }

  /** 初次加载：初始化速度基线后开始轮询 */
  async function load(code: string) {
    stop()
    currentCode = code
    devices.value = []
    search.value = ''
    resetState()
    loading.value = true
    const data = await deviceApi.load(code)
    loading.value = false
    if (!data) return

    const now = Date.now()
    lastTraffic = new Map()
    for (const dev of data) {
      dev.tx_speed = 0
      dev.rx_speed = 0
      lastTraffic.set(dev.device_id, { tx: dev.tx_bytes, rx: dev.rx_bytes })
    }
    lastFetchTime = now
    devices.value = data
    start()
  }

  /** 轮询一次：差分算网速 + 累计历史 */
  async function poll() {
    if (!currentCode || document.visibilityState === 'hidden') return
    const data = await deviceApi.list(currentCode)
    if (!data) return

    const now = Date.now()
    const elapsed = lastFetchTime > 0 ? (now - lastFetchTime) / 1000 : 0
    const newTraffic = new Map<string, TrafficPoint>()

    for (const dev of data) {
      const prev = lastTraffic.get(dev.device_id)
      if (prev && elapsed > 0) {
        dev.tx_speed = Math.round(Math.max(0, (dev.tx_bytes || 0) - prev.tx) / elapsed)
        dev.rx_speed = Math.round(Math.max(0, (dev.rx_bytes || 0) - prev.rx) / elapsed)
      } else {
        dev.tx_speed = 0
        dev.rx_speed = 0
      }
      newTraffic.set(dev.device_id, { tx: dev.tx_bytes || 0, rx: dev.rx_bytes || 0 })
    }

    lastTraffic = newTraffic
    lastFetchTime = now
    devices.value = data

    // 按 IP 累计速度历史
    const ipSpeed = new Map<string, TrafficPoint>()
    for (const dev of data) {
      const key = dev.ip ?? `no-ip-${dev.device_id}`
      const point = ipSpeed.get(key) ?? { tx: 0, rx: 0 }
      point.tx += dev.tx_speed ?? 0
      point.rx += dev.rx_speed ?? 0
      ipSpeed.set(key, point)
    }
    for (const [key, point] of ipSpeed) {
      let history = speedHistory.get(key)
      if (!history) {
        history = { tx: [], rx: [] }
        speedHistory.set(key, history)
      }
      history.tx.push(point.tx)
      history.rx.push(point.rx)
      if (history.tx.length > HISTORY_SIZE) {
        history.tx.shift()
        history.rx.shift()
      }
    }
  }

  function historyOf(key: string): SpeedHistory {
    return speedHistory.get(key) ?? EMPTY_HISTORY
  }

  function toggleGroup(key: string) {
    groupExpanded[key] = !groupExpanded[key]
  }

  function toggleChart(key: string) {
    chartExpanded[key] = !chartExpanded[key]
  }

  /** 按 IP 分组（合并本地/远程来源），并附带聚合统计 */
  const mergedDevices = computed<DeviceGroup[]>(() => {
    const q = search.value.toLowerCase()
    const filtered = devices.value.filter(
      (d) =>
        (d.ip && d.ip.includes(q)) ||
        d.device_id.toLowerCase().includes(q) ||
        d.device_name.toLowerCase().includes(q),
    )

    const groups = new Map<string, DeviceInfo[]>()
    for (const dev of filtered) {
      const key = dev.ip ?? `no-ip-${dev.device_id}`
      const list = groups.get(key) ?? []
      list.push(dev)
      groups.set(key, list)
    }

    const result: DeviceGroup[] = []
    for (const [key, devs] of groups) {
      const latencies = devs
        .map((d) => d.latency_ms)
        .filter((l): l is number => l !== null && l !== undefined)
      result.push({
        key,
        ip: key.startsWith('no-ip-') ? null : key,
        devices: devs,
        hasOnline: devs.some((d) => d.status === 'Online'),
        hasRemote: devs.some((d) => d.status === 'Remote'),
        canDelete: devs.every((d) => d.status !== 'Online' && d.status !== 'Remote'),
        bestLatency: latencies.length > 0 ? Math.min(...latencies) : null,
        totalTxBytes: devs.reduce((sum, d) => sum + d.tx_bytes, 0),
        totalRxBytes: devs.reduce((sum, d) => sum + d.rx_bytes, 0),
        totalTxSpeed: devs.reduce((sum, d) => sum + (d.tx_speed ?? 0), 0),
        totalRxSpeed: devs.reduce((sum, d) => sum + (d.rx_speed ?? 0), 0),
      })
    }
    return result
  })

  onUnmounted(stop)

  return {
    devices,
    loading,
    search,
    mergedDevices,
    groupExpanded,
    chartExpanded,
    load,
    stop,
    historyOf,
    toggleGroup,
    toggleChart,
  }
}