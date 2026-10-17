<script setup lang="ts">
import {
  ArrowLeft,
  ChartLine,
  ChevronDown,
  ChevronRight,
  Clipboard,
  CircleCheck,
  CircleX,
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
import QRCode from 'qrcode'
import { useRoute, useRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import { deviceApi, managedDeviceApi, networkApi, settingsApi } from '@/api/modules'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import BaseModal from '@/components/BaseModal.vue'
import Ikev2AccessModal from '@/components/Ikev2AccessModal.vue'
import WireGuardAccessModal from '@/components/WireGuardAccessModal.vue'
import LatencyBadge from '@/components/LatencyBadge.vue'
import SpeedChart from '@/components/SpeedChart.vue'
import StatusBadge from '@/components/StatusBadge.vue'
import { useDeviceMonitor, type DeviceGroup } from '@/composables/useDeviceMonitor'
import { useToast } from '@/composables/useToast'
import type { ClientType, DeviceInfo, DeviceIpType, Ikev2InputRoute, ManagedConfigMutation, NetworkInfo } from '@/types'
import { copyText } from '@/utils/clipboard'
import { formatBytes, formatSpeed } from '@/utils/format'
import { ADVANCED_CONFIG_TEMPLATE, emptyVntClientConfig, validateAdvancedToml } from '@/utils/managedConfigToml'

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
const pendingCreateIpSuggestion = ref(false)
const vntAdvancedToml = ref('')
const vntAdvancedError = ref('')
const vntSubscriptionServer = ref('')

const deviceForm = ref({
  device_id: '',
  device_name: '',
  ip: '',
  ip_type: 'Dynamic' as DeviceIpType,
  client_type: 'VNT' as ClientType,
  ikev2_password: '',
  output_subnets: [] as string[],
  input_routes: [] as Ikev2InputRoute[],
  wireguard_dns: '',
  wireguard_private_key: '',
  vnt_config: emptyVntClientConfig(),
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

watch(availableIpSuggestion, (suggestion) => {
  if (!pendingCreateIpSuggestion.value || editingDevice.value || deviceForm.value.ip || !suggestion) return
  deviceForm.value.ip = suggestion
  pendingCreateIpSuggestion.value = false
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
  const prefix = deviceForm.value.client_type === 'IKEV2' ? 'ikev2' : deviceForm.value.client_type === 'WIREGUARD' ? 'wg' : 'vnt'
  deviceForm.value.device_id = `${prefix}-${randomValue(12, '0123456789abcdef')}`
}

function generatePassword() {
  deviceForm.value.ikev2_password = randomValue(24, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_')
  showIkev2Password.value = true
}

function changeClientType() {
  generateDeviceId()
  if (deviceForm.value.client_type === 'WIREGUARD') {
    deviceForm.value.ip_type = 'Static'
  }
  if (deviceForm.value.client_type === 'IKEV2') {
    generatePassword()
  } else {
    deviceForm.value.ikev2_password = ''
    deviceForm.value.output_subnets = []
    deviceForm.value.input_routes = []
    deviceForm.value.wireguard_dns = ''
    deviceForm.value.wireguard_private_key = ''
    showIkev2Password.value = false
  }
}

function addOutputSubnet() {
  deviceForm.value.output_subnets.push('')
}

function addInputRoute() {
  deviceForm.value.input_routes.push({ subnet: '', target_ip: '' })
}

function parseWireguardDns() {
  return deviceForm.value.wireguard_dns.split(/[,，\s]+/).map((value) => value.trim()).filter(Boolean)
}

async function copyCredential(value: string) {
  if (!value) return
  try {
    await copyText(value)
    toast.success('已复制到剪贴板')
  } catch {
    toast.error('复制失败，请手动复制')
  }
}

async function loadVntAccessDefaults() {
  try {
    const settings = await settingsApi.getClientAccess()
    vntSubscriptionServer.value = settings.subscription_server.trim()
    const configured = (settings.traffic_servers.length
      ? settings.traffic_servers
      : [settings.subscription_server]
    ).map((server) => server.trim()).filter(Boolean)
    deviceForm.value.vnt_config.current_server = configured[0] ?? ''
    deviceForm.value.vnt_config.other_servers = configured.slice(1)
  } catch {
    // 输入框保持为空，由用户在当前设备上填写。
  }
}

async function openCreateDevice() {
  editingDevice.value = null
  const suggestedIp = availableIpSuggestion.value
  deviceForm.value = {
    device_id: '',
    device_name: '',
    ip: suggestedIp ?? '',
    ip_type: 'Dynamic',
    client_type: 'VNT',
    ikev2_password: '',
    output_subnets: [],
    input_routes: [],
    wireguard_dns: '',
    wireguard_private_key: '',
    vnt_config: emptyVntClientConfig(),
  }
  pendingCreateIpSuggestion.value = suggestedIp === undefined
  generateDeviceId()
  showIkev2Password.value = false
  vntSubscriptionServer.value = ''
  await loadVntAccessDefaults()
  vntAdvancedToml.value = ADVANCED_CONFIG_TEMPLATE
  vntAdvancedError.value = ''
  showDeviceModal.value = true
}

function localDevice(group: DeviceGroup) {
  return group.devices.find((device) => device.server_addr === null)
}

function onlineVntSyncState(group: DeviceGroup): 'available' | 'unavailable' | null {
  const device = localDevice(group)
  if (device?.client_type !== 'VNT' || device.status !== 'Online') return null
  return device.subscription_online ? 'available' : 'unavailable'
}

function subscriptionOnlyOnline(group: DeviceGroup) {
  const device = localDevice(group)
  return (
    device?.client_type === 'VNT' &&
    device.managed &&
    !device.relay_online &&
    device.subscription_online
  )
}

function vntSyncTooltip(group: DeviceGroup) {
  const device = localDevice(group)
  if (!device) return ''
  const state = device.subscription_online
    ? '订阅链接实时同步已连接'
    : device.subscription_issued
      ? '当前连接未使用订阅链接，无法实时同步'
      : '尚未签发订阅链接，无法实时同步'
  return device.subscription_error ? `${state}\n同步异常：${device.subscription_error}` : state
}

function differingSessionIp(group: DeviceGroup) {
  const device = localDevice(group)
  if (device?.status !== 'Online' || !device.current_ip || device.current_ip === device.ip) {
    return null
  }
  return device.current_ip
}

async function openEditDevice(group: DeviceGroup) {
  const device = localDevice(group)
  if (!device) return
  editingDevice.value = device
  deviceForm.value = {
    device_id: device.device_id,
    device_name: device.device_name,
    ip: device.ip ?? '',
    ip_type: device.client_type === 'WIREGUARD' ? 'Static' : (device.ip_type ?? 'Dynamic'),
    client_type: device.client_type,
    ikev2_password: '',
    output_subnets: [...(device.client_type === 'WIREGUARD' ? device.wireguard_output_subnets : device.ikev2_output_subnets)],
    input_routes: (device.client_type === 'WIREGUARD' ? device.wireguard_input_routes : device.ikev2_input_routes).map((route) => ({ ...route })),
    wireguard_dns: device.client_type === 'WIREGUARD' ? device.wireguard_dns.join(', ') : '',
    wireguard_private_key: '',
    vnt_config: emptyVntClientConfig(),
  }
  showIkev2Password.value = false
  vntAdvancedToml.value = ''
  vntAdvancedError.value = ''
  showDeviceModal.value = true
  if (device.client_type === 'VNT') {
    try {
      const managed = await managedDeviceApi.get(networkCode.value, device.device_id)
      deviceForm.value.vnt_config = managed.client_config
      vntSubscriptionServer.value = managed.subscription_server
      vntAdvancedToml.value = managed.advanced_config_toml
    } catch (error) {
      showDeviceModal.value = false
      toast.error(error instanceof ApiError ? error.message : '加载 VNT 配置失败')
    }
  }
}

function differingSessionName(group: DeviceGroup) {
  const device = localDevice(group)
  if (device?.status !== 'Online' || !device.current_device_name || device.current_device_name === device.device_name) {
    return null
  }
  return device.current_device_name
}

async function submitDevice() {
  if (formSubmitting.value) return
  let advancedToml = ''
  if (deviceForm.value.client_type === 'VNT') {
    const currentServer = deviceForm.value.vnt_config.current_server.trim()
    const otherServers = deviceForm.value.vnt_config.other_servers.map((server) => server.trim()).filter(Boolean)
    const trafficServers = [currentServer, ...otherServers].filter(Boolean)
    if (new Set(trafficServers).size !== trafficServers.length) {
      toast.error('服务器地址不能重复')
      return
    }
    deviceForm.value.vnt_config.current_server = currentServer
    deviceForm.value.vnt_config.other_servers = otherServers
    vntAdvancedError.value = ''
    try {
      validateAdvancedToml(vntAdvancedToml.value)
      advancedToml = vntAdvancedToml.value
    } catch (error) {
      vntAdvancedError.value = error instanceof Error ? error.message : 'TOML 格式错误'
      toast.error('请先修正高级 TOML 中的错误')
      return
    }
  }
  formSubmitting.value = true
  try {
    let managedMutation: ManagedConfigMutation | undefined
    if (editingDevice.value) {
      if (deviceForm.value.client_type === 'VNT') {
        managedMutation = await managedDeviceApi.update(
          networkCode.value,
          deviceForm.value.device_id,
          advancedToml,
          vntSubscriptionServer.value.trim(),
          [deviceForm.value.vnt_config.current_server, ...deviceForm.value.vnt_config.other_servers].filter(Boolean),
          deviceForm.value.device_name,
          deviceForm.value.ip,
          deviceForm.value.ip_type,
        )
      } else await deviceApi.update(editingDevice.value.device_id, {
          network_code: networkCode.value,
          device_name: deviceForm.value.device_name,
          ip: deviceForm.value.ip,
          ip_type: deviceForm.value.client_type === 'WIREGUARD' ? 'Static' : deviceForm.value.ip_type,
          ...(deviceForm.value.client_type === 'IKEV2' && deviceForm.value.ikev2_password
            ? { ikev2_password: deviceForm.value.ikev2_password }
            : {}),
          ...(deviceForm.value.client_type === 'IKEV2'
            ? {
                ikev2_output_subnets: deviceForm.value.output_subnets.map((subnet) => subnet.trim()).filter(Boolean),
                ikev2_input_routes: deviceForm.value.input_routes.map((route) => ({
                  subnet: route.subnet.trim(),
                  target_ip: route.target_ip.trim(),
                })),
              }
            : {}),
          ...(deviceForm.value.client_type === 'WIREGUARD'
            ? {
                wireguard_output_subnets: deviceForm.value.output_subnets.map((subnet) => subnet.trim()).filter(Boolean),
                wireguard_input_routes: deviceForm.value.input_routes.map((route) => ({ subnet: route.subnet.trim(), target_ip: route.target_ip.trim() })),
                wireguard_dns: parseWireguardDns(),
                ...(deviceForm.value.wireguard_private_key.trim()
                  ? { wireguard_private_key: deviceForm.value.wireguard_private_key.trim() }
                  : {}),
              }
            : {}),
        })
    } else {
      const payload = {
        network_code: networkCode.value,
        device_id: deviceForm.value.device_id,
        ...(deviceForm.value.client_type !== 'VNT' ? { device_name: deviceForm.value.device_name } : {}),
        ip: deviceForm.value.ip,
        ip_type: deviceForm.value.client_type === 'WIREGUARD' ? 'Static' : deviceForm.value.ip_type,
        client_type: deviceForm.value.client_type,
        ...(deviceForm.value.client_type === 'IKEV2'
          ? {
              ikev2_password: deviceForm.value.ikev2_password,
              ikev2_output_subnets: deviceForm.value.output_subnets.map((subnet) => subnet.trim()).filter(Boolean),
              ikev2_input_routes: deviceForm.value.input_routes.map((route) => ({
                subnet: route.subnet.trim(),
                target_ip: route.target_ip.trim(),
              })),
            }
          : {}),
        ...(deviceForm.value.client_type === 'WIREGUARD'
          ? {
              wireguard_output_subnets: deviceForm.value.output_subnets.map((subnet) => subnet.trim()).filter(Boolean),
              wireguard_input_routes: deviceForm.value.input_routes.map((route) => ({ subnet: route.subnet.trim(), target_ip: route.target_ip.trim() })),
              wireguard_dns: parseWireguardDns(),
              ...(deviceForm.value.wireguard_private_key.trim()
                ? { wireguard_private_key: deviceForm.value.wireguard_private_key.trim() }
                : {}),
            }
          : {}),
      }
      if (deviceForm.value.client_type === 'VNT') {
        const result = await managedDeviceApi.create({
          network_code: networkCode.value,
          device_id: deviceForm.value.device_id,
          device_name: deviceForm.value.device_name,
          ip: deviceForm.value.ip,
          ip_type: deviceForm.value.ip_type,
          config_toml: advancedToml,
          subscription_server: vntSubscriptionServer.value.trim(),
          traffic_servers_override: [deviceForm.value.vnt_config.current_server, ...deviceForm.value.vnt_config.other_servers].filter(Boolean),
        })
        managedMutation = result
        if (result.subscription) await showSubscription(result.subscription)
      } else await deviceApi.add(payload)
    }
    showDeviceModal.value = false
    if (managedMutation) {
      const message = {
        queued: '配置已推送，等待客户端应用',
        unchanged: '配置已保存，配置内容未变化',
        not_connected: editingDevice.value?.status === 'Offline' ? '配置已保存' : '配置已保存，客户端连接后将补发',
        registering: '配置已保存，客户端注册完成后将补发',
        timeout: '配置已保存，当前连接发送超时，将在重连后补发',
        closed: '配置已保存，连接已关闭，将在重连后补发',
      }[managedMutation.push_status]
      toast.success(message)
    } else {
      toast.success(editingDevice.value ? '设备已更新' : '设备已添加')
    }
    void monitor.load(networkCode.value)
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '提交失败')
  } finally {
    formSubmitting.value = false
  }
}

const accessDevice = ref<DeviceInfo | null>(null)
const wireGuardAccessDevice = ref<DeviceInfo | null>(null)

function openIkev2Access(group: DeviceGroup) {
  const device = localDevice(group)
  if (device?.client_type === 'IKEV2') accessDevice.value = device
}

function openWireGuardAccess(group: DeviceGroup) {
  const device = localDevice(group)
  if (device?.client_type === 'WIREGUARD') wireGuardAccessDevice.value = device
}

const subscription = ref('')
const subscriptionQr = ref('')

async function showSubscription(link: string) {
  subscription.value = link
  try {
    subscriptionQr.value = await QRCode.toDataURL(link, { width: 320, margin: 1 })
  } catch {
    subscriptionQr.value = ''
  }
}

async function openVntSubscription(group: DeviceGroup) {
  const device = localDevice(group)
  if (!device || device.client_type !== 'VNT') return
  try {
    const result = await managedDeviceApi.subscription(networkCode.value, device.device_id)
    await showSubscription(result.subscription)
    void monitor.load(networkCode.value)
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '获取订阅链接失败')
  }
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
                <div class="flex flex-wrap items-center gap-1.5">
                  <StatusBadge :status="group.hasOnline ? 'Online' : group.hasRemote ? 'Remote' : 'Offline'" />
                  <span
                    v-if="subscriptionOnlyOnline(group)"
                    class="inline-flex items-center gap-1 rounded-full bg-violet-50 px-2 py-0.5 text-[10px] font-semibold text-violet-700 dark:bg-violet-500/10 dark:text-violet-300"
                    :title="vntSyncTooltip(group)"
                  >
                    <span class="h-1.5 w-1.5 rounded-full bg-violet-500" />
                    订阅在线
                  </span>
                </div>
              </td>
              <td class="px-4 py-3">
                <div class="flex items-center gap-2 font-medium text-slate-900 dark:text-slate-100">
                  <span>{{ group.devices[0]?.device_name }}</span>
                  <span
                    v-if="group.devices[0]?.client_type !== 'VNT'"
                    class="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-semibold text-slate-500 dark:bg-slate-700 dark:text-slate-300"
                  >{{ group.devices[0]?.client_type || 'VNT' }}</span>
                  <span
                    v-else-if="onlineVntSyncState(group)"
                    class="inline-flex"
                    :title="vntSyncTooltip(group)"
                  >
                    <CircleCheck
                      v-if="onlineVntSyncState(group) === 'available'"
                      :size="15"
                      class="text-emerald-600 dark:text-emerald-400"
                      aria-label="实时同步可用"
                    />
                    <CircleX
                      v-else
                      :size="15"
                      class="text-slate-400 dark:text-slate-500"
                      aria-label="实时同步不可用"
                    />
                  </span>
                </div>
                <div class="font-mono text-xs text-slate-400 dark:text-slate-500">{{ group.devices[0]?.device_id }}</div>
                <div v-if="differingSessionName(group)" class="mt-0.5 text-xs text-amber-600 dark:text-amber-400">
                  当前名称：{{ differingSessionName(group) }}
                </div>
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
                    v-if="localDevice(group)?.client_type === 'VNT'"
                    class="flex h-7 w-7 items-center justify-center rounded-lg text-violet-500 transition hover:bg-violet-50 hover:text-violet-700 dark:hover:bg-violet-500/10"
                    title="订阅链接二维码"
                    @click="openVntSubscription(group)"
                  ><KeyRound :size="15" /></button>
                  <button
                    v-if="localDevice(group)?.client_type === 'IKEV2'"
                    class="flex h-7 w-7 items-center justify-center rounded-lg text-cyan-500 transition hover:bg-cyan-50 hover:text-cyan-700 dark:hover:bg-cyan-500/10 dark:hover:text-cyan-300"
                    title="IKEv2 接入说明"
                    @click="openIkev2Access(group)"
                  >
                    <KeyRound :size="15" />
                  </button>
                  <button
                    v-if="localDevice(group)?.client_type === 'WIREGUARD'"
                    class="flex h-7 w-7 items-center justify-center rounded-lg text-slate-400 hover:bg-blue-50 hover:text-blue-600 dark:hover:bg-blue-500/10 dark:hover:text-blue-400"
                    title="WireGuard 接入配置"
                    @click="openWireGuardAccess(group)"
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
      extra-wide
      @close="showDeviceModal = false"
    >
      <form class="space-y-4" @submit.prevent="submitDevice">
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">设备类型</label>
          <select v-model="deviceForm.client_type" :class="inputClass" :disabled="Boolean(editingDevice)" @change="changeClientType">
            <option value="VNT">VNT</option>
            <option value="IKEV2">IKEv2</option>
            <option value="WIREGUARD">WireGuard</option>
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
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">设备名称</label>
          <input v-model.trim="deviceForm.device_name" type="text" :class="inputClass" maxlength="128" required />
        </div>
        <section v-if="deviceForm.client_type === 'VNT'" class="space-y-4 rounded-xl border border-blue-100 bg-blue-50/40 p-4 dark:border-blue-500/20 dark:bg-blue-500/5">
          <div>
            <h4 class="text-sm font-semibold text-slate-800 dark:text-slate-100">VNT 客户端配置</h4>
            <p class="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">
              {{ editingDevice?.subscription_online ? '该客户端通过订阅链接接入，保存后会立即推送；实际应用结果会显示在设备状态中。' : '当前没有通过订阅链接验证的同步连接；配置会保存在服务端，客户端下次使用订阅链接启动时会获取。' }}
            </p>
          </div>
          <div class="grid gap-4 sm:grid-cols-2">
            <div class="sm:col-span-2">
              <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">订阅服务器地址</label>
              <input v-model.trim="vntSubscriptionServer" type="text" :class="inputClass" placeholder="tcp://vpn.example.com:29872" />
              <p class="mt-1.5 text-xs text-slate-400">留空时使用“客户端接入”中配置的订阅服务器。</p>
            </div>
            <div class="sm:col-span-2">
              <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">流量服务器地址</label>
              <input v-model.trim="deviceForm.vnt_config.current_server" type="text" :class="inputClass" placeholder="quic://vpn.example.com:29872" />
              <p class="mt-1.5 text-xs text-slate-400">留空时使用上面的订阅服务器地址。</p>
              <div class="mb-1.5 mt-4 flex items-center justify-between gap-3">
                <label class="text-sm font-medium text-slate-700 dark:text-slate-300">其他流量服务器地址</label>
                <button type="button" class="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-700" @click="deviceForm.vnt_config.other_servers.push('')"><Plus :size="13" />添加地址</button>
              </div>
              <div class="space-y-2">
                <div v-for="(_, index) in deviceForm.vnt_config.other_servers" :key="index" class="flex gap-2">
                  <input v-model.trim="deviceForm.vnt_config.other_servers[index]" type="text" :class="inputClass" placeholder="quic://vpn.example.com:29872" />
                  <button type="button" class="rounded-lg border border-slate-200 px-3 text-slate-400 hover:text-red-500 dark:border-slate-600" title="删除其他服务器地址" @click="deviceForm.vnt_config.other_servers.splice(index, 1)"><Trash2 :size="15" /></button>
                </div>
              </div>
            </div>
          </div>

          <details class="rounded-lg border border-slate-200 bg-white/70 dark:border-slate-700 dark:bg-slate-900/40">
            <summary class="cursor-pointer px-3 py-2 text-sm font-medium text-slate-700 dark:text-slate-200">高级配置</summary>
            <div class="border-t border-slate-100 p-3 dark:border-slate-700">
              <textarea v-model="vntAdvancedToml" rows="24" :class="inputClass" class="resize-y font-mono text-xs leading-5" spellcheck="false" placeholder="# 按需填写 VNT 客户端 TOML 配置；留空则使用客户端默认值&#10;# 例如：&#10;# mtu = 1400（范围：576-1500）&#10;# compress = true" />
              <p class="mt-2 text-xs text-slate-400">只填写需要由服务端同步的配置。未填写的字段不固化默认值；MTU 可设置为 576–1500。服务端地址、证书、设备身份和虚拟 IP 请在基础区域配置。</p>
              <p v-if="vntAdvancedError" class="mt-2 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-600 dark:bg-red-500/10 dark:text-red-300">{{ vntAdvancedError }}</p>
            </div>
          </details>
        </section>
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
        <div v-if="deviceForm.client_type === 'IKEV2' || deviceForm.client_type === 'WIREGUARD'" class="space-y-2">
          <div class="flex items-center justify-between gap-3">
            <div>
              <label class="block text-sm font-medium text-slate-700 dark:text-slate-300">出口子网</label>
              <p class="mt-0.5 text-xs text-slate-400">该设备后方可达的 IPv4 CIDR。</p>
            </div>
            <button type="button" class="flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs text-slate-600 hover:text-cyan-600 dark:border-slate-600 dark:text-slate-300" @click="addOutputSubnet"><Plus :size="14" />添加</button>
          </div>
          <div v-for="(_, index) in deviceForm.output_subnets" :key="`output-${index}`" class="flex gap-2">
            <input v-model.trim="deviceForm.output_subnets[index]" type="text" :class="inputClass" placeholder="例如：192.168.10.0/24" required />
            <button type="button" class="rounded-lg border border-slate-200 px-3 text-slate-400 hover:text-red-500 dark:border-slate-600" title="删除出口子网" @click="deviceForm.output_subnets.splice(index, 1)"><Trash2 :size="15" /></button>
          </div>
        </div>
        <div v-if="deviceForm.client_type === 'IKEV2' || deviceForm.client_type === 'WIREGUARD'" class="space-y-2">
          <div class="flex items-center justify-between gap-3">
            <div>
              <label class="block text-sm font-medium text-slate-700 dark:text-slate-300">入口路由</label>
              <p class="mt-0.5 text-xs text-slate-400">把目标子网流量交给指定的 VNT 虚拟 IP。</p>
            </div>
            <button type="button" class="flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs text-slate-600 hover:text-cyan-600 dark:border-slate-600 dark:text-slate-300" @click="addInputRoute"><Plus :size="14" />添加</button>
          </div>
          <div v-for="(route, index) in deviceForm.input_routes" :key="`input-${index}`" class="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
            <input v-model.trim="route.subnet" type="text" :class="inputClass" placeholder="目标 CIDR" required />
            <input v-model.trim="route.target_ip" type="text" :class="inputClass" placeholder="目标 VNT IP" required />
            <button type="button" class="rounded-lg border border-slate-200 px-3 text-slate-400 hover:text-red-500 dark:border-slate-600" title="删除入口路由" @click="deviceForm.input_routes.splice(index, 1)"><Trash2 :size="15" /></button>
          </div>
        </div>
        <div v-if="deviceForm.client_type === 'WIREGUARD'">
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">客户端 DNS <span class="font-normal text-slate-400">（可选）</span></label>
          <input v-model.trim="deviceForm.wireguard_dns" type="text" :class="inputClass" placeholder="1.1.1.1, 8.8.8.8" />
          <p class="mt-1.5 text-xs leading-5 text-slate-400 dark:text-slate-500">写入该设备配置文件的 DNS 行；多个 IPv4 地址用逗号或空格分隔，留空则不添加。</p>
        </div>
        <div v-if="deviceForm.client_type === 'WIREGUARD'">
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">设备私钥 <span class="font-normal text-slate-400">（可选）</span></label>
          <input v-model.trim="deviceForm.wireguard_private_key" type="text" :class="inputClass" class="font-mono text-xs" :placeholder="editingDevice ? '留空保留当前私钥' : '留空自动生成'" autocomplete="off" spellcheck="false" />
          <p class="mt-1.5 text-xs leading-5 text-slate-400 dark:text-slate-500">标准 WireGuard 私钥（base64，44 位）；同一私钥只能绑定一台设备。{{ editingDevice ? '更换后需要重新下载客户端配置。' : '' }}</p>
        </div>
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">IP 地址</label>
          <input v-model.trim="deviceForm.ip" type="text" :class="inputClass" :placeholder="ipPlaceholder" required @input="pendingCreateIpSuggestion = false" />
        </div>
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">IP 类型</label>
          <select v-model="deviceForm.ip_type" :class="inputClass" :disabled="deviceForm.client_type === 'WIREGUARD'">
            <option value="Static">静态IP</option>
            <option value="Dynamic">动态IP</option>
            <option value="Fixed">固定 IP</option>
          </select>
          <p v-if="deviceForm.client_type === 'WIREGUARD'" class="mt-1.5 text-xs leading-5 text-slate-400 dark:text-slate-500">
            WireGuard 固定使用静态 IP，且不会按租期回收。
          </p>
          <p v-else-if="deviceForm.ip_type === 'Static'" class="mt-1.5 text-xs leading-5 text-slate-400 dark:text-slate-500">
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

    <BaseModal :open="Boolean(subscription)" title="设备订阅链接" @close="subscription = ''; subscriptionQr = ''">
      <div class="space-y-4 text-center">
        <img v-if="subscriptionQr" :src="subscriptionQr" alt="订阅链接二维码" class="mx-auto h-80 w-80 rounded-lg" />
        <textarea :value="subscription" readonly rows="4" class="field w-full break-all font-mono text-xs" />
        <button class="primary-button mx-auto" @click="copyCredential(subscription)"><Clipboard :size="15" />复制订阅链接</button>
        <p class="text-xs text-slate-500">VNT 客户端扫描二维码即可添加订阅配置；点击设备行的钥匙按钮可随时重新打开，请勿发送到不可信渠道。</p>
      </div>
    </BaseModal>

    <Ikev2AccessModal
      :open="Boolean(accessDevice)"
      :network-code="networkCode"
      :device-id="accessDevice?.device_id ?? ''"
      @close="accessDevice = null"
    />
    <WireGuardAccessModal
      :open="Boolean(wireGuardAccessDevice)"
      :network-code="networkCode"
      :device-id="wireGuardAccessDevice?.device_id ?? ''"
      @close="wireGuardAccessDevice = null"
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
