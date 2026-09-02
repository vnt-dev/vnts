<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { SPEED_HISTORY_SIZE, type SpeedHistory } from '@/composables/useDeviceMonitor'
import { useTheme } from '@/composables/useTheme'
import { formatSpeed } from '@/utils/format'

const props = withDefaults(defineProps<{ history: SpeedHistory; height?: number }>(), {
  height: 140,
})

const { theme } = useTheme()

const canvasRef = ref<HTMLCanvasElement | null>(null)
const peakLabel = ref('峰值: -')
let resizeObserver: ResizeObserver | null = null

/** 读取 CSS 变量颜色（随主题切换），取不到时使用兜底值 */
function cssColor(name: string, fallback: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return v || fallback
}

/** 将数值取整到合适的刻度上限 */
function niceNumber(val: number): number {
  const units = [
    1024,
    10 * 1024,
    100 * 1024,
    1024 * 1024,
    10 * 1024 * 1024,
    100 * 1024 * 1024,
    1024 * 1024 * 1024,
  ]
  for (const u of units) {
    if (val <= u) return u
  }
  return Math.ceil(val / (1024 * 1024 * 1024)) * 1024 * 1024 * 1024
}

function draw() {
  const canvas = canvasRef.value
  if (!canvas) return
  const ctx = canvas.getContext('2d')
  if (!ctx) return

  const dpr = window.devicePixelRatio || 1
  const rect = canvas.getBoundingClientRect()
  const w = rect.width
  const h = rect.height
  canvas.width = Math.round(w * dpr)
  canvas.height = Math.round(h * dpr)
  ctx.scale(dpr, dpr)

  const { tx, rx } = props.history
  const padTop = 6
  const padBottom = 4
  const chartW = w
  const chartH = h - padTop - padBottom

  ctx.fillStyle = cssColor('--chart-bg', '#ffffff')
  ctx.fillRect(0, 0, w, h)

  const all = [...tx, ...rx]
  const maxVal = all.length > 0 ? Math.max(...all) : 0
  const niceMax = niceNumber(maxVal > 0 ? maxVal : 1024)
  peakLabel.value = `峰值: ${formatSpeed(niceMax)}`

  // 网格线
  const gridLines = 4
  ctx.strokeStyle = cssColor('--chart-grid', 'rgba(148, 163, 184, 0.25)')
  ctx.lineWidth = 1
  for (let i = 0; i <= gridLines; i++) {
    const y = padTop + (chartH / gridLines) * i
    ctx.beginPath()
    ctx.moveTo(0, y)
    ctx.lineTo(chartW, y)
    ctx.stroke()
  }

  const drawSeries = (data: number[], stroke: string, fill: string) => {
    if (data.length < 2) return
    const step = chartW / (SPEED_HISTORY_SIZE - 1)
    const offset = SPEED_HISTORY_SIZE - data.length

    // 填充区域
    ctx.beginPath()
    ctx.moveTo(offset * step, padTop + chartH)
    for (let i = 0; i < data.length; i++) {
      ctx.lineTo((offset + i) * step, padTop + chartH - (data[i] / niceMax) * chartH)
    }
    ctx.lineTo((offset + data.length - 1) * step, padTop + chartH)
    ctx.closePath()
    ctx.fillStyle = fill
    ctx.fill()

    // 曲线
    ctx.beginPath()
    for (let i = 0; i < data.length; i++) {
      const x = (offset + i) * step
      const y = padTop + chartH - (data[i] / niceMax) * chartH
      if (i === 0) ctx.moveTo(x, y)
      else ctx.lineTo(x, y)
    }
    ctx.strokeStyle = stroke
    ctx.lineWidth = 1.5
    ctx.stroke()
  }

  drawSeries(rx, '#3b82f6', 'rgba(59, 130, 246, 0.10)')
  drawSeries(tx, '#10b981', 'rgba(16, 185, 129, 0.10)')
}

// 历史数据持续追加（数组原地 push/shift），深度监听触发重绘
watch(
  () => props.history,
  () => {
    nextTick(draw)
  },
  { deep: true },
)

// 主题切换后重绘 canvas
watch(theme, () => {
  nextTick(draw)
})

onMounted(() => {
  nextTick(draw)
  const canvas = canvasRef.value
  if (canvas) {
    resizeObserver = new ResizeObserver(() => draw())
    resizeObserver.observe(canvas)
  }
})

onBeforeUnmount(() => {
  resizeObserver?.disconnect()
})
</script>

<template>
  <div>
    <div class="mb-2 flex items-center gap-4 text-xs text-slate-500 dark:text-slate-400">
      <span class="flex items-center gap-1.5">
        <span class="inline-block h-0.5 w-3 rounded bg-blue-500"></span>
        下载速度
      </span>
      <span class="flex items-center gap-1.5">
        <span class="inline-block h-0.5 w-3 rounded bg-emerald-500"></span>
        上传速度
      </span>
      <span class="ml-auto font-medium text-slate-400 dark:text-slate-500">{{ peakLabel }}</span>
    </div>
    <canvas ref="canvasRef" class="block w-full rounded-md" :style="{ height: `${height}px` }"></canvas>
  </div>
</template>