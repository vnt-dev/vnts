<script setup lang="ts">
import {
  ArrowLeft,
  ChartLine,
  ChevronDown,
  ChevronRight,
  Clipboard,
  Eye,
  EyeOff,
  KeyRound,
  LoaderCircle,
  Pencil,
  Plus,
  Search,
  RefreshCw,
  Trash2,
} from '@lucide/vue'
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import { deviceApi, networkApi } from '@/api/modules'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import BaseModal from '@/components/BaseModal.vue'
import Ikev2AccessModal from '@/components/Ikev2AccessModal.vue'
import LatencyBadge from '@/components/LatencyBadge.vue'
import SpeedChart from '@/components/SpeedChart.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { useDeviceMonitor, type DeviceGroup } from '@/composables/useDeviceMonitor'
import { useToast } from '@/composables/useToast'
import type { ClientType, DeviceInfo, DeviceIpType, NetworkInfo } from '@/types'
import { formatBytes, formatSpeed } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const toast = useToast()

const networkCode = computed(() => (route.params.code as string | undefined) ?? '')
const monitor = useDeviceMonitor()
const { devices, mergedDevices, loading, search } = monitor
const currentNetwork = ref<NetworkInfo | null>(null)

async function loadCurrentNetwork(code: string) {
  currentNetwork.value = null
  try {
    const networks = await networkApi.list()
    if (networkCode.value === code) {
      currentNetwork.value = networks.find((network) => network.network_code === code) ?? null
    }
  } catch {
    // 设备列表仍可正常使用；此时仅无法给出可用 IP 示例。
  }
}

watch(
  networkCode,
  (code) => {
    if (code) {
      void monitor.load(code)
      void loadCurrentNetwork(code)
    }
  },
  { immediate: true },
)

const searchInputClass =
  'w-full rounded-lg border border-slate-200 bg-white py-2 pl-9 pr-3.5 text-sm text-slate-800 placeholder:text-slate-400 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200 dark:placeholder:text-slate-500 dark:focus:border-blue-500 dark:focus:ring-blue-500/20'
const inputClass =
  'w-full rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm text-slate-800 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 disabled:bg-slate-50 disabled:text-slate-500 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200 dark:focus:border-blue-500 dark:focus:ring-blue-500/20 dark:disabled:bg-slate-800/50 dark:disabled:text-slate-600'

function goBack() {
  router.push({ name: 'networks' })
}

// ---------- 新增 / 编辑设备 ----------
const showDeviceModal = ref(false)
const editingDevice = ref<DeviceInfo | null>(null)
const formSubmitting = ref(false)
const deviceForm = ref({
  device_id: '',
  ip: '',
  ip_type: 'Dynamic' as DeviceIpType,
  client_type: 'VNT' as ClientType,
  ikev2_password: '',
})
const showIkev2Password = ref(false)

function ipv4ToNumber(value: string) {
  const parts = value.split('.')
  if (parts.length !== 4) return null
  const octets = parts.map(Number)
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null
  return octets.reduce((result, octet) => result * 256 + octet, 0)
}

function numberToIpv4(value: number) {
  return [
    Math.floor(value / 16_777_216),
    Math.floor(value / 65_536) % 256,
    Math.floor(value / 256) % 256,
    value % 256,
  ].join('.')
}

const availableIpSuggestion = computed<string | null | undefined>(() => {
  if (!currentNetwork.value || loading.value) return undefined
  const [networkAddress, prefixText] = currentNetwork.value.net.split('/')
  const address = ipv4ToNumber(networkAddress ?? '')
  const prefix = Number(prefixText)
  if (address === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 30) return undefined

  const blockSize = 2 ** (32 - prefix)
  const networkStart = Math.floor(address / blockSize) * blockSize
  const broadcast = networkStart + blockSize - 1
  let candidate = networkStart + 1
  const occupied = new Set<number>()
  const reserve = (ip: string | null) => {
    if (!ip) return
    const value = ipv4ToNumber(ip)
    if (value !== null && value > networkStart && value < broadcast) occupied.add(value)
  }
  reserve(currentNetwork.value.gateway)
  for (const device of devices.value) {
    reserve(device.ip)
    reserve(device.current_ip)
  }

  for (const value of [...occupied].sort((left, right) => left - right)) {
    if (value < candidate) continue
    if (value > candidate) break
    candidate += 1
  }
  return candidate < broadcast ? numberToIpv4(candidate) : null
})

const ipPlaceholder = computed(() => {
  if (editingDevice.value) return '请输入 IP 地址'
  if (availableIpSuggestion.value === undefined) return '正在计算可用 IP…'
  return availableIpSuggestion.value ? `例如：${availableIpSuggestion.value}` : 'IP 已用尽'
})

function randomValue(length: number, alphabet: string) {
  const limit = Math.floor(256 / alphabet.length) * alphabet.length
  let value = ''
  while (value.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length + 8))) {
      if (byte < limit) value += alphabet[byte % alphabet.length]
      if (value.length === length) break
    }
  }
  return value
}

function generateDeviceId() {
  const prefix = deviceForm.value.client_type === 'IKEV2' ? 'ikev2' : 'vnt'
  deviceForm.value.device_id = `${prefix}-${randomValue(12, '0123456789abcdef')}`
}

function generatePassword() {
  deviceForm.value.ikev2_password = randomValue(24, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_')
  showIkev2Password.value = true
}

function changeClientType() {
  generateDeviceId()
  if (deviceForm.value.client_type === 'IKEV2') {
    generatePassword()
  } else {
    deviceForm.value.ikev2_password = ''
    showIkev2Password.value = false
  }
}

async function copyCredential(value: string) {
  if (!value) return
  await navigator.clipboard.writeText(value)
  toast.success('已复制到剪贴板')
}

function openCreateDevice() {
  editingDevice.value = null
  deviceForm.value = { device_id: '', ip: '', ip_type: 'Dynamic', client_type: 'VNT', ikev2_password: '' }
  generateDeviceId()
  showIkev2Password.value = false
  showDeviceModal.value = true
}

function localDevice(group: DeviceGroup) {
  return group.devices.find((device) => device.server_addr === null)
}

function differingSessionIp(group: DeviceGroup) {
  const device = localDevice(group)
  if (device?.status !== 'Online' || !device.current_ip || device.current_ip === device.ip) {
    return null
  }
  return device.current_ip
}

function openEditDevice(group: DeviceGroup) {
  const device = localDevice(group)
  if (!device) return
  editingDevice.value = device
  deviceForm.value = {
    device_id: device.device_id,
    ip: device.ip ?? '',
    ip_type: device.ip_type ?? 'Dynamic',
    client_type: device.client_type,
    ikev2_password: '',
  }
  showIkev2Password.value = false
  showDeviceModal.value = true
}

async function submitDevice() {
  if (formSubmitting.value) return
  formSubmitting.value = true
  try {
    if (editingDevice.value) {
      await deviceApi.update(editingDevice.value.device_id, {
        network_code: networkCode.value,
        ip: deviceForm.value.ip,
        ip_type: deviceForm.value.ip_type,
        ...(deviceForm.value.client_type === 'IKEV2' && deviceForm.value.ikev2_password
          ? { ikev2_password: deviceForm.value.ikev2_password }
          : {}),
      })
    } else {
      await deviceApi.add({
        network_code: networkCode.value,
        device_id: deviceForm.value.device_id,
        ip: deviceForm.value.ip,
        ip_type: deviceForm.value.ip_type,
        client_type: deviceForm.value.client_type,
        ...(deviceForm.value.client_type === 'IKEV2'
          ? { ikev2_password: deviceForm.value.ikev2_password }
          : {}),
      })
    }
    showDeviceModal.value = false
    toast.success(editingDevice.value ? '设备已更新' : '设备已添加')
    void monitor.load(networkCode.value)
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '提交失败')
  } finally {
    formSubmitting.value = false
  }
}

const accessDevice = ref<DeviceInfo | null>(null)

function openIkev2Access(group: DeviceGroup) {
  const device = localDevice(group)
  if (device?.client_type === 'IKEV2') accessDevice.value = device
}

// ---------- 删除设备 ----------
const confirmOpen = ref(false)
const confirmMessage = ref('')
const deleteTarget = ref<DeviceInfo | null>(null)
const deleting = ref(false)

function confirmRemove(group: DeviceGroup) {
  const dev = localDevice(group)
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
          class="rounded-lg border border-slate-200 bg-white p-2 text-slate-500 shadow-sm transition hover:bg-slate-50 hover:text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400 dark:hover:bg-slate-700/60 dark:hover:text-slate-200"
          title="返回网络列表"
          @click="goBack"
        >
          <ArrowLeft :size="16" />
        </button>
        <div>
          <h2 class="text-xl font-bold text-slate-900 dark:text-slate-100">网络详情</h2>
          <p class="mt-0.5 font-mono text-sm text-slate-400 dark:text-slate-500">网络: {{ networkCode }}</p>
        </div>
      </div>
      <div class="flex w-full items-center gap-3 lg:w-auto">
        <div class="relative min-w-0 flex-1 lg:w-72">
          <Search :size="15" class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          <input v-model="search" type="text" :class="searchInputClass" placeholder="搜索 IP 或设备 ID..." />
        </div>
        <button
          class="flex shrink-0 items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-blue-700"
          @click="openCreateDevice"
        >
          <Plus :size="16" />
          新增设备
        </button>
      </div>
    </div>

    <!-- 设备表格 -->
    <div v-if="loading" class="flex justify-center bg-white py-20 shadow-sm dark:bg-slate-800">
      <LoaderCircle :size="28" class="animate-spin text-blue-500" />
    </div>

    <div v-else class="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-800">
      <table class="w-full min-w-[1360px] text-left text-sm">
        <thead>
          <tr class="border-b border-slate-100 bg-slate-50/80 text-xs text-slate-500 dark:border-slate-700 dark:bg-slate-800/80 dark:text-slate-400">
            <th class="w-16 px-4 py-3"></th>
            <th class="px-4 py-3 font-semibold">状态</th>
            <th class="px-4 py-3 font-semibold">设备名称 / ID</th>
            <th class="px-4 py-3 font-semibold">IP 地址</th>
            <th class="px-4 py-3 font-semibold">上报出口网段</th>
            <th class="px-4 py-3 font-semibold">IP 类型</th>
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
            <tr class="border-b border-slate-50 transition hover:bg-slate-50/60 dark:border-slate-700/60 dark:hover:bg-slate-700/40">
              <td class="px-4 py-3">
                <div class="flex items-center gap-1">
                  <button
                    v-if="group.devices.length > 1"
                    class="rounded p-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-600 dark:text-slate-500 dark:hover:bg-slate-700 dark:hover:text-slate-300"
                    title="展开来源"
                    @click="monitor.toggleGroup(group.key)"
                  >
                    <ChevronDown v-if="monitor.groupExpanded[group.key]" :size="14" />
                    <ChevronRight v-else :size="14" />
                  </button>
                  <button
                    class="rounded p-1 text-slate-400 transition hover:bg-blue-50 hover:text-blue-600 dark:text-slate-500 dark:hover:bg-blue-500/10 dark:hover:text-blue-400"
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
                <div class="flex items-center gap-2 font-medium text-slate-900 dark:text-slate-100">
                  <span>{{ group.devices[0]?.device_name }}</span>
                  <span
                    class="rounded px-1.5 py-0.5 text-[10px] font-semibold"
                    :class="group.devices[0]?.client_type === 'IKEV2' ? 'bg-cyan-50 text-cyan-700 dark:bg-cyan-500/10 dark:text-cyan-300' : 'bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-300'"
                  >{{ group.devices[0]?.client_type || 'VNT' }}</span>
                </div>
                <div class="font-mono text-xs text-slate-400 dark:text-slate-500">{{ group.devices[0]?.device_id }}</div>
                <div v-if="group.devices.length > 1" class="mt-0.5 text-xs text-blue-500 dark:text-blue-400">
                  {{ group.devices.length }} 个来源
                </div>
              </td>
              <td class="px-4 py-3 font-mono text-slate-600 dark:text-slate-400">
                <span>{{ group.ip || '-' }}</span>
                <span v-if="differingSessionIp(group)" class="ml-1 text-xs text-amber-600 dark:text-amber-400">
                  （当前使用：{{ differingSessionIp(group) }}）
                </span>
              </td>
              <td class="px-4 py-3">
                <div v-if="group.advertisedSubnets.length" class="flex max-w-72 flex-wrap gap-1">
                  <span
                    v-for="subnet in group.advertisedSubnets"
                    :key="subnet"
                    class="rounded bg-violet-50 px-1.5 py-0.5 font-mono text-xs text-violet-700 dark:bg-violet-500/10 dark:text-violet-300"
                  >
                    {{ subnet }}
                  </span>
                </div>
                <span v-else class="text-slate-300 dark:text-slate-600">-</span>
              </td>
              <td class="px-4 py-3 text-xs font-medium">
                <span
                  v-if="localDevice(group)?.ip_type"
                  :class="localDevice(group)?.ip_type === 'Fixed' ? 'text-red-600 dark:text-red-400' : localDevice(group)?.ip_type === 'Static' ? 'text-amber-600 dark:text-amber-400' : 'text-blue-600 dark:text-blue-400'"
                >
                  {{ localDevice(group)?.ip_type === 'Fixed' ? '固定 IP' : localDevice(group)?.ip_type === 'Static' ? '静态IP' : '动态IP' }}
                </span>
                <span v-else class="text-slate-300 dark:text-slate-600">-</span>
              </td>
              <td class="px-4 py-3 text-slate-500 dark:text-slate-400">{{ group.devices[0]?.device_version }}</td>
              <td class="px-4 py-3">
                <LatencyBadge :ms="group.bestLatency" />
              </td>
              <td class="px-3 py-3">
                <div class="flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                  ↑ <span class="tabular-nums">{{ formatBytes(group.totalTxBytes) }}</span>
                </div>
                <div class="mt-0.5 flex items-center gap-1 text-blue-600 dark:text-blue-400">
                  ↓ <span class="tabular-nums">{{ formatBytes(group.totalRxBytes) }}</span>
                </div>
              </td>
              <td class="px-3 py-3">
                <div class="flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                  ↑ <span class="tabular-nums">{{ formatSpeed(group.totalTxSpeed) }}</span>
                </div>
                <div class="mt-0.5 flex items-center gap-1 text-blue-600 dark:text-blue-400">
                  ↓ <span class="tabular-nums">{{ formatSpeed(group.totalRxSpeed) }}</span>
                </div>
              </td>
              <td class="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">
                {{ group.devices[0]?.last_connect_time }}
                <div v-if="group.devices[0]?.disconnect_time" class="text-red-400 dark:text-red-400">
                  离线于: {{ group.devices[0].disconnect_time }}
                </div>
              </td>
              <td class="px-4 py-3">
                <div class="flex items-center gap-1">
                  <button
                    v-if="localDevice(group)"
                    class="flex h-7 w-7 items-center justify-center rounded-lg text-slate-400 transition hover:bg-blue-50 hover:text-blue-600 dark:text-slate-500 dark:hover:bg-blue-500/10 dark:hover:text-blue-400"
                    title="编辑设备"
                    @click="openEditDevice(group)"
                  >
                    <Pencil :size="15" />
                  </button>
                  <button
                    v-if="localDevice(group)?.client_type === 'IKEV2'"
                    class="flex h-7 w-7 items-center justify-center rounded-lg text-cyan-500 transition hover:bg-cyan-50 hover:text-cyan-700 dark:hover:bg-cyan-500/10 dark:hover:text-cyan-300"
                    title="IKEv2 接入说明"
                    @click="openIkev2Access(group)"
                  >
                    <KeyRound :size="15" />
                  </button>
                  <button
                    v-if="group.canDelete"
                    class="flex h-7 w-7 items-center justify-center rounded-lg text-slate-400 transition hover:bg-red-50 hover:text-red-600 dark:text-slate-500 dark:hover:bg-red-500/10 dark:hover:text-red-400"
                    title="删除设备"
                    @click="confirmRemove(group)"
                  >
                    <Trash2 :size="15" />
                  </button>
                  <span
                    v-else
                    class="flex h-7 w-7 cursor-not-allowed items-center justify-center rounded-lg text-slate-200 dark:text-slate-700"
                    :title="group.hasOnline ? '在线设备无法删除' : '远程设备无法删除'"
                  >
                    <Trash2 :size="15" />
                  </span>
                </div>
              </td>
            </tr>

            <!-- 网速历史图表行 -->
            <tr v-if="monitor.chartExpanded[group.key]" class="border-b border-slate-50 bg-white dark:border-slate-700/60 dark:bg-slate-800">
              <td colspan="12" class="px-4 py-3">
                <div class="rounded-lg border border-slate-100 bg-white px-4 py-3 dark:border-slate-700 dark:bg-slate-900">
                  <SpeedChart :history="monitor.historyOf(group.key)" />
                </div>
              </td>
            </tr>

            <!-- 多来源展开行 -->
            <template v-if="monitor.groupExpanded[group.key] && group.devices.length > 1">
              <tr
                v-for="dev in group.devices"
                :key="dev.device_id"
                class="border-b border-slate-50 bg-slate-50/50 dark:border-slate-700/60 dark:bg-slate-700/30"
              >
              <td class="px-4 py-3"></td>
              <td class="px-4 py-3">
                <StatusBadge :status="dev.status" />
              </td>
              <td class="px-4 py-3">
                <span v-if="dev.server_addr" class="font-mono text-xs font-medium text-blue-600 dark:text-blue-400">
                  {{ dev.server_addr }}
                </span>
                <span v-else class="text-xs font-medium text-emerald-600 dark:text-emerald-400">本地</span>
                <span class="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-500 dark:bg-slate-700 dark:text-slate-300">{{ dev.client_type || 'VNT' }}</span>
              </td>
              <td class="px-4 py-3 text-xs text-slate-400 dark:text-slate-500">-</td>
              <td class="px-4 py-3">
                <div v-if="dev.advertised_subnets.length" class="flex max-w-72 flex-wrap gap-1">
                  <span
                    v-for="subnet in dev.advertised_subnets"
                    :key="subnet"
                    class="rounded bg-violet-50 px-1.5 py-0.5 font-mono text-xs text-violet-700 dark:bg-violet-500/10 dark:text-violet-300"
                  >
                    {{ subnet }}
                  </span>
                </div>
                <span v-else class="text-slate-300 dark:text-slate-600">-</span>
              </td>
              <td class="px-4 py-3 text-xs text-slate-400 dark:text-slate-500">-</td>
              <td class="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{{ dev.device_version }}</td>
              <td class="px-4 py-3 text-xs">
                <LatencyBadge :ms="dev.latency_ms" />
              </td>
              <td class="px-3 py-3 text-xs">
                <div class="text-emerald-600 dark:text-emerald-400">↑ {{ formatBytes(dev.tx_bytes) }}</div>
                <div class="mt-0.5 text-blue-600 dark:text-blue-400">↓ {{ formatBytes(dev.rx_bytes) }}</div>
              </td>
              <td class="px-3 py-3 text-xs">
                <div class="text-emerald-600 dark:text-emerald-400">↑ {{ formatSpeed(dev.tx_speed ?? 0) }}</div>
                <div class="mt-0.5 text-blue-600 dark:text-blue-400">↓ {{ formatSpeed(dev.rx_speed ?? 0) }}</div>
              </td>
              <td class="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{{ dev.last_connect_time }}</td>
              <td class="px-4 py-3"></td>
            </tr>
            </template>
          </template>

          <tr v-if="mergedDevices.length === 0">
            <td colspan="12" class="px-4 py-16 text-center text-sm text-slate-400 dark:text-slate-500">
              暂无设备数据
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <BaseModal
      :open="showDeviceModal"
      :title="editingDevice ? '编辑设备' : '新增设备'"
      @close="showDeviceModal = false"
    >
      <form class="space-y-4" @submit.prevent="submitDevice">
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">设备类型</label>
          <select v-model="deviceForm.client_type" :class="inputClass" :disabled="Boolean(editingDevice)" @change="changeClientType">
            <option value="VNT">VNT</option>
            <option value="IKEV2">IKEv2</option>
          </select>
          <p v-if="editingDevice" class="mt-1.5 text-xs text-slate-400">设备创建后不能修改类型。</p>
        </div>
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">{{ deviceForm.client_type === 'IKEV2' ? '用户名（设备 ID）' : '设备 ID' }}</label>
          <div class="flex gap-2">
            <input v-model.trim="deviceForm.device_id" type="text" :class="inputClass" :disabled="Boolean(editingDevice)" :maxlength="deviceForm.client_type === 'IKEV2' ? 48 : 64" required />
            <button v-if="!editingDevice" type="button" class="rounded-lg border border-slate-200 px-3 text-slate-500 hover:text-cyan-600 dark:border-slate-600" :title="deviceForm.client_type === 'IKEV2' ? '重新生成用户名' : '重新生成设备 ID'" @click="generateDeviceId"><RefreshCw :size="15" /></button>
            <button v-if="!editingDevice" type="button" class="rounded-lg border border-slate-200 px-3 text-slate-500 hover:text-cyan-600 dark:border-slate-600" :title="deviceForm.client_type === 'IKEV2' ? '复制用户名' : '复制设备 ID'" @click="copyCredential(deviceForm.device_id)"><Clipboard :size="15" /></button>
          </div>
        </div>
        <div v-if="deviceForm.client_type === 'IKEV2'">
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">{{ editingDevice ? '重置密码' : '密码' }}</label>
          <div class="flex gap-2">
            <div class="relative min-w-0 flex-1">
              <input v-model="deviceForm.ikev2_password" :type="showIkev2Password ? 'text' : 'password'" :class="inputClass" :placeholder="editingDevice ? '留空表示保留当前密码' : ''" :required="!editingDevice" />
              <button type="button" class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-600" title="显示或隐藏密码" @click="showIkev2Password = !showIkev2Password"><EyeOff v-if="showIkev2Password" :size="16" /><Eye v-else :size="16" /></button>
            </div>
            <button type="button" class="rounded-lg border border-slate-200 px-3 text-slate-500 hover:text-cyan-600 dark:border-slate-600" title="生成新密码" @click="generatePassword"><RefreshCw :size="15" /></button>
            <button type="button" class="rounded-lg border border-slate-200 px-3 text-slate-500 hover:text-cyan-600 dark:border-slate-600" title="复制密码" :disabled="!deviceForm.ikev2_password" @click="copyCredential(deviceForm.ikev2_password)"><Clipboard :size="15" /></button>
          </div>
        </div>
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">IP 地址</label>
          <input v-model.trim="deviceForm.ip" type="text" :class="inputClass" :placeholder="ipPlaceholder" required />
        </div>
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">IP 类型</label>
          <select v-model="deviceForm.ip_type" :class="inputClass">
            <option value="Static">静态IP</option>
            <option value="Dynamic">动态IP</option>
            <option value="Fixed">固定 IP</option>
          </select>
          <p v-if="deviceForm.ip_type === 'Static'" class="mt-1.5 text-xs leading-5 text-slate-400 dark:text-slate-500">
            注册时优先使用客户端提交的 IP，且不会按租期回收。
          </p>
          <p v-else-if="deviceForm.ip_type === 'Dynamic'" class="mt-1.5 text-xs leading-5 text-slate-400 dark:text-slate-500">
            注册时优先使用客户端提交的 IP，租期到期后会释放 IP。
          </p>
          <p v-else class="mt-1.5 text-xs leading-5 text-slate-400 dark:text-slate-500">
            强制使用服务端设置的 IP，客户端不能修改，且不会按租期回收。
          </p>
        </div>
        <div class="flex justify-end gap-3 pt-2">
          <button type="button" class="rounded-lg px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-700" @click="showDeviceModal = false">
            取消
          </button>
          <button type="submit" :disabled="formSubmitting" class="flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white disabled:opacity-60">
            <LoaderCircle v-if="formSubmitting" :size="14" class="animate-spin" />
            {{ formSubmitting ? '提交中...' : '确定' }}
          </button>
        </div>
      </form>
    </BaseModal>

    <Ikev2AccessModal
      :open="Boolean(accessDevice)"
      :network-code="networkCode"
      :device-id="accessDevice?.device_id ?? ''"
      @close="accessDevice = null"
    />

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
