<script setup lang="ts">
import {
  ArrowLeft,
  ChartLine,
  ChevronDown,
  ChevronRight,
  LoaderCircle,
  Search,
  Trash2,
} from '@lucide/vue'
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import { deviceApi } from '@/api/modules'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import LatencyBadge from '@/components/LatencyBadge.vue'
import SpeedChart from '@/components/SpeedChart.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { useDeviceMonitor, type DeviceGroup } from '@/composables/useDeviceMonitor'
import { useToast } from '@/composables/useToast'
import type { DeviceInfo } from '@/types'
import { formatBytes, formatSpeed } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const toast = useToast()

const networkCode = computed(() => (route.params.code as string | undefined) ?? '')
const monitor = useDeviceMonitor()
const { mergedDevices, loading, search } = monitor

watch(
  networkCode,
  (code) => {
    if (code) void monitor.load(code)
  },
  { immediate: true },
)

const searchInputClass =
  'w-full rounded-lg border border-slate-200 bg-white py-2 pl-9 pr-3.5 text-sm text-slate-800 placeholder:text-slate-400 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100'

function goBack() {
  router.push({ name: 'networks' })
}

// ---------- 删除设备 ----------
const confirmOpen = ref(false)
const confirmMessage = ref('')
const deleteTarget = ref<DeviceInfo | null>(null)
const deleting = ref(false)

function confirmRemove(group: DeviceGroup) {
  const dev = group.devices[0]
  if (!dev) return
  deleteTarget.value = dev
  confirmMessage.value = `确定要删除设备 "${dev.device_name}" (${dev.device_id}) 吗？此操作不可撤销。`
  confirmOpen.value = true
}

async function executeDelete() {
  if (!deleteTarget.value || deleting.value) return
  deleting.value = true
  try {
    await deviceApi.remove(networkCode.value, deleteTarget.value.device_id)
    confirmOpen.value = false
    toast.success('设备已删除')
    void monitor.load(networkCode.value)
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '删除设备失败')
  } finally {
    deleting.value = false
  }
}
</script>

<template>
  <div>
    <!-- 页头 -->
    <div class="mb-6 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
      <div class="flex items-center gap-3">
        <button
          class="rounded-lg border border-slate-200 bg-white p-2 text-slate-500 shadow-sm transition hover:bg-slate-50 hover:text-slate-700"
          title="返回网络列表"
          @click="goBack"
        >
          <ArrowLeft :size="16" />
        </button>
        <div>
          <h2 class="text-xl font-bold text-slate-900">设备详情</h2>
          <p class="mt-0.5 font-mono text-sm text-slate-400">网络: {{ networkCode }}</p>
        </div>
      </div>
      <div class="relative w-full lg:w-72">
        <Search :size="15" class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
        <input v-model="search" type="text" :class="searchInputClass" placeholder="搜索 IP 或设备 ID..." />
      </div>
    </div>

    <!-- 设备表格 -->
    <div v-if="loading" class="flex justify-center bg-white py-20 shadow-sm">
      <LoaderCircle :size="28" class="animate-spin text-blue-500" />
    </div>

    <div v-else class="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
      <table class="w-full min-w-[1080px] text-left text-sm">
        <thead>
          <tr class="border-b border-slate-100 bg-slate-50/80 text-xs text-slate-500">
            <th class="w-16 px-4 py-3"></th>
            <th class="px-4 py-3 font-semibold">状态</th>
            <th class="px-4 py-3 font-semibold">设备名称 / ID</th>
            <th class="px-4 py-3 font-semibold">IP 地址</th>
            <th class="px-4 py-3 font-semibold">版本</th>
            <th class="px-4 py-3 font-semibold">延迟</th>
            <th class="px-3 py-3 font-semibold">流量 <span class="font-normal">(上/下)</span></th>
            <th class="px-3 py-3 font-semibold">网速 <span class="font-normal">(上/下)</span></th>
            <th class="px-4 py-3 font-semibold">最后连接</th>
            <th class="px-4 py-3 font-semibold">操作</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="group in mergedDevices" :key="group.key">
            <!-- 主行 -->
            <tr class="border-b border-slate-50 transition hover:bg-slate-50/60">
              <td class="px-4 py-3">
                <div class="flex items-center gap-1">
                  <button
                    v-if="group.devices.length > 1"
                    class="rounded p-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-600"
                    title="展开来源"
                    @click="monitor.toggleGroup(group.key)"
                  >
                    <ChevronDown v-if="monitor.groupExpanded[group.key]" :size="14" />
                    <ChevronRight v-else :size="14" />
                  </button>
                  <button
                    class="rounded p-1 text-slate-400 transition hover:bg-blue-50 hover:text-blue-600"
                    :title="monitor.chartExpanded[group.key] ? '收起网速历史' : '查看网速历史'"
                    @click="monitor.toggleChart(group.key)"
                  >
                    <ChartLine :size="13" />
                  </button>
                </div>
              </td>
              <td class="px-4 py-3">
                <StatusBadge :status="group.hasOnline ? 'Online' : group.hasRemote ? 'Remote' : 'Offline'" />
              </td>
              <td class="px-4 py-3">
                <div class="font-medium text-slate-900">{{ group.devices[0]?.device_name }}</div>
                <div class="font-mono text-xs text-slate-400">{{ group.devices[0]?.device_id }}</div>
                <div v-if="group.devices.length > 1" class="mt-0.5 text-xs text-blue-500">
                  {{ group.devices.length }} 个来源
                </div>
              </td>
              <td class="px-4 py-3 font-mono text-slate-600">{{ group.ip || '-' }}</td>
              <td class="px-4 py-3 text-slate-500">{{ group.devices[0]?.device_version }}</td>
              <td class="px-4 py-3">
                <LatencyBadge :ms="group.bestLatency" />
              </td>
              <td class="px-3 py-3">
                <div class="flex items-center gap-1 text-emerald-600">
                  ↑ <span class="tabular-nums">{{ formatBytes(group.totalTxBytes) }}</span>
                </div>
                <div class="mt-0.5 flex items-center gap-1 text-blue-600">
                  ↓ <span class="tabular-nums">{{ formatBytes(group.totalRxBytes) }}</span>
                </div>
              </td>
              <td class="px-3 py-3">
                <div class="flex items-center gap-1 text-emerald-600">
                  ↑ <span class="tabular-nums">{{ formatSpeed(group.totalTxSpeed) }}</span>
                </div>
                <div class="mt-0.5 flex items-center gap-1 text-blue-600">
                  ↓ <span class="tabular-nums">{{ formatSpeed(group.totalRxSpeed) }}</span>
                </div>
              </td>
              <td class="px-4 py-3 text-xs text-slate-500">
                {{ group.devices[0]?.last_connect_time }}
                <div v-if="group.devices[0]?.disconnect_time" class="text-red-400">
                  离线于: {{ group.devices[0].disconnect_time }}
                </div>
              </td>
              <td class="px-4 py-3">
                <button
                  v-if="group.canDelete"
                  class="rounded-lg p-1.5 text-slate-400 transition hover:bg-red-50 hover:text-red-600"
                  title="删除设备"
                  @click="confirmRemove(group)"
                >
                  <Trash2 :size="15" />
                </button>
                <span
                  v-else
                  class="inline-block cursor-not-allowed p-1.5 text-slate-200"
                  :title="group.hasOnline ? '在线设备无法删除' : '远程设备无法删除'"
                >
                  <Trash2 :size="15" />
                </span>
              </td>
            </tr>

            <!-- 网速历史图表行 -->
            <tr v-if="monitor.chartExpanded[group.key]" class="border-b border-slate-50 bg-white">
              <td colspan="10" class="px-4 py-3">
                <div class="rounded-lg border border-slate-100 bg-white px-4 py-3">
                  <SpeedChart :history="monitor.historyOf(group.key)" />
                </div>
              </td>
            </tr>

            <!-- 多来源展开行 -->
            <template v-if="monitor.groupExpanded[group.key] && group.devices.length > 1">
              <tr
                v-for="dev in group.devices"
                :key="dev.device_id"
                class="border-b border-slate-50 bg-slate-50/50"
              >
              <td class="px-4 py-3"></td>
              <td class="px-4 py-3">
                <StatusBadge :status="dev.status" />
              </td>
              <td class="px-4 py-3">
                <span v-if="dev.server_addr" class="font-mono text-xs font-medium text-blue-600">
                  {{ dev.server_addr }}
                </span>
                <span v-else class="text-xs font-medium text-emerald-600">本地</span>
              </td>
              <td class="px-4 py-3 text-xs text-slate-400">-</td>
              <td class="px-4 py-3 text-xs text-slate-500">{{ dev.device_version }}</td>
              <td class="px-4 py-3 text-xs">
                <LatencyBadge :ms="dev.latency_ms" />
              </td>
              <td class="px-3 py-3 text-xs">
                <div class="text-emerald-600">↑ {{ formatBytes(dev.tx_bytes) }}</div>
                <div class="mt-0.5 text-blue-600">↓ {{ formatBytes(dev.rx_bytes) }}</div>
              </td>
              <td class="px-3 py-3 text-xs">
                <div class="text-emerald-600">↑ {{ formatSpeed(dev.tx_speed ?? 0) }}</div>
                <div class="mt-0.5 text-blue-600">↓ {{ formatSpeed(dev.rx_speed ?? 0) }}</div>
              </td>
              <td class="px-4 py-3 text-xs text-slate-500">{{ dev.last_connect_time }}</td>
              <td class="px-4 py-3"></td>
            </tr>
            </template>
          </template>

          <tr v-if="mergedDevices.length === 0">
            <td colspan="10" class="px-4 py-16 text-center text-sm text-slate-400">
              暂无设备数据
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 删除确认 -->
    <ConfirmDialog
      :open="confirmOpen"
      :message="confirmMessage"
      :loading="deleting"
      @close="confirmOpen = false"
      @confirm="executeDelete"
    />
  </div>
</template>