<script setup lang="ts">
import { Clipboard, Download, Eye, EyeOff, LoaderCircle, ShieldAlert } from '@lucide/vue'
import { computed, ref, watch } from 'vue'
import { ApiError } from '@/api/client'
import { deviceApi, settingsApi } from '@/api/modules'
import { useToast } from '@/composables/useToast'
import type { DeviceIkev2AccessInfo } from '@/types'
import BaseModal from './BaseModal.vue'

const props = defineProps<{ open: boolean; networkCode: string; deviceId: string }>()
const emit = defineEmits<{ close: [] }>()
const toast = useToast()
const loading = ref(false)
const info = ref<DeviceIkev2AccessInfo | null>(null)
const showPassword = ref(false)
const platform = ref<'windows' | 'apple' | 'android' | 'strongswan'>('windows')
const platforms: Array<{ id: 'windows' | 'apple' | 'android' | 'strongswan'; label: string }> = [
  { id: 'windows', label: 'Windows 11' },
  { id: 'apple', label: 'macOS / iOS' },
  { id: 'android', label: 'Android' },
  { id: 'strongswan', label: 'strongSwan' },
]

const serverAddress = computed(() => info.value?.service.server_address || '尚未配置')
const remoteIdentity = computed(() => info.value?.service.remote_id || '尚未配置')
const windowsCommand = computed(() => `Set-VpnConnectionIPsecConfiguration -ConnectionName "VNT-${props.networkCode}" -EncryptionMethod GCMAES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -CipherTransformConstants GCMAES256 -AuthenticationTransformConstants GCMAES256 -PfsGroup None -Force`)
const strongSwanConfig = computed(() => `connections {
  vnt-${props.networkCode} {
    remote_addrs = ${serverAddress.value}
    vips = 0.0.0.0
    proposals = aes256gcm16-prfsha256-modp2048
    children { vnt { remote_ts = ${info.value?.network_net ?? 'VNT_SUBNET'} } }
    local { auth = eap-mschapv2; eap_id = ${info.value?.username ?? 'YOUR_USERNAME'} }
    remote { auth = pubkey; id = ${remoteIdentity.value} }
  }
}
secrets {
  eap-vnt { id = ${info.value?.username ?? 'YOUR_USERNAME'}; secret = "${showPassword.value ? info.value?.password ?? 'YOUR_PASSWORD' : 'YOUR_PASSWORD'}" }
}`)

async function load() {
  if (!props.open || !props.networkCode || !props.deviceId) return
  loading.value = true
  info.value = null
  showPassword.value = false
  try {
    info.value = await deviceApi.getIkev2Access(props.networkCode, props.deviceId)
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '加载 IKEv2 接入信息失败')
  } finally {
    loading.value = false
  }
}

watch(() => [props.open, props.networkCode, props.deviceId], load, { immediate: true })

async function copy(value: string) {
  await navigator.clipboard.writeText(value)
  toast.success('已复制到剪贴板')
}

async function downloadCa() {
  try {
    await settingsApi.downloadIkev2Ca('der')
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '下载 CA 证书失败')
  }
}

async function downloadServerCertificate() {
  try {
    await settingsApi.downloadIkev2ServerCertificate('der')
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '下载服务器证书失败')
  }
}
</script>

<template>
  <BaseModal :open="open" title="IKEv2 接入说明" wide @close="emit('close')">
    <div v-if="loading" class="flex justify-center py-16">
      <LoaderCircle :size="28" class="animate-spin text-cyan-500" />
    </div>
    <div v-else-if="info" class="space-y-5 text-sm">
      <div
        v-if="!info.service.enabled || !info.service.runtime_active || info.service.runtime_error"
        class="flex gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 leading-6 text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300"
      >
        <ShieldAlert :size="18" class="mt-0.5 shrink-0" />
        <span>{{ info.service.runtime_error || '全局 IKEv2 服务尚未启用或未运行，请先到系统设置完成基础配置。' }}</span>
      </div>

      <div class="grid gap-3 sm:grid-cols-2">
        <div class="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
          <div class="text-xs text-slate-400">服务器地址 / 远程ID</div>
          <div class="mt-1 break-all font-mono text-slate-700 dark:text-slate-200">{{ serverAddress }} / {{ remoteIdentity }}</div>
        </div>
        <div class="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
          <div class="text-xs text-slate-400">目标网络</div>
          <div class="mt-1 font-mono text-slate-700 dark:text-slate-200">{{ info.network_code }} · {{ info.network_net }}</div>
        </div>
      </div>

      <div class="space-y-3 rounded-lg border border-cyan-200 bg-cyan-50/50 p-4 dark:border-cyan-500/30 dark:bg-cyan-500/5">
        <div>
          <div class="text-xs text-slate-400">用户名（设备 ID）</div>
          <div class="mt-1 flex items-center gap-2">
            <code class="min-w-0 flex-1 break-all text-slate-800 dark:text-slate-100">{{ info.username }}</code>
            <button type="button" class="icon-button" title="复制用户名" @click="copy(info.username)"><Clipboard :size="15" /></button>
          </div>
        </div>
        <div>
          <div class="text-xs text-slate-400">密码</div>
          <div class="mt-1 flex items-center gap-2">
            <code class="min-w-0 flex-1 break-all text-slate-800 dark:text-slate-100">{{ showPassword ? info.password : '••••••••••••••••••••••••' }}</code>
            <button type="button" class="icon-button" title="显示或隐藏密码" @click="showPassword = !showPassword"><EyeOff v-if="showPassword" :size="15" /><Eye v-else :size="15" /></button>
            <button type="button" class="icon-button" title="复制密码" @click="copy(info.password)"><Clipboard :size="15" /></button>
          </div>
        </div>
      </div>

      <div v-if="info.service.ca_download_available || info.service.server_certificate_download_available" class="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-200 p-3 dark:border-slate-700">
        <span class="min-w-56 flex-1 text-slate-600 dark:text-slate-300">正常连接应安装并信任 VNT IKEv2 CA；服务器证书下载用于诊断或需要直接信任叶证书的客户端。</span>
        <div class="flex flex-wrap gap-2">
          <button v-if="info.service.ca_download_available" type="button" class="secondary" @click="downloadCa"><Download :size="14" />下载 CA</button>
          <button v-if="info.service.server_certificate_download_available" type="button" class="secondary" @click="downloadServerCertificate"><Download :size="14" />下载服务器证书</button>
        </div>
      </div>

      <div class="flex gap-1 overflow-x-auto rounded-lg bg-slate-100 p-1 dark:bg-slate-900">
        <button v-for="item in platforms" :key="item.id" type="button" class="whitespace-nowrap rounded-md px-3 py-1.5 text-xs font-semibold" :class="platform === item.id ? 'bg-white text-cyan-700 shadow-sm dark:bg-slate-700 dark:text-cyan-300' : 'text-slate-500'" @click="platform = item.id">{{ item.label }}</button>
      </div>

      <div class="guide">
        <template v-if="platform === 'windows'">
          <h4>Windows 11</h4>
          <ol><li>安装并信任 CA 证书。</li><li>添加 VPN，类型选择 IKEv2，服务器填写 <code>{{ serverAddress }}</code>。</li><li>登录信息选择“用户名和密码”，填写上方凭据。</li><li>在管理员 PowerShell 中执行：</li></ol>
          <pre>{{ windowsCommand }}</pre>
        </template>
        <template v-else-if="platform === 'apple'">
          <h4>macOS / iOS</h4>
          <ol><li>安装 CA 并启用完全信任。</li><li>新增 IKEv2 VPN，服务器填写 <code>{{ serverAddress }}</code>，远程ID填写 <code>{{ remoteIdentity }}</code>。</li><li>本地ID留空，认证方式选择用户名，填写上方凭据。</li></ol>
        </template>
        <template v-else-if="platform === 'android'">
          <h4>Android</h4>
          <ol><li>把下载的 CA 安装为“VPN 和应用的 CA 证书”。</li><li>新增类型为“IKEv2/IPSec MSCHAPv2”的 VPN。</li><li>服务器地址填写 <code>{{ serverAddress }}</code>。</li><li>IPSec 标识符填写用户名（设备 ID）<code>{{ info.username }}</code>。</li><li>“IPSec CA 证书”明确选择刚安装的 VNT IKEv2 CA，不要选择“不验证服务器”。</li><li>填写上方用户名和密码。</li></ol>
          <p v-if="serverAddress !== remoteIdentity" class="text-amber-600 dark:text-amber-300">Android 原生客户端会以服务器地址作为远程ID；当前服务器地址与远程ID不同，可能无法通过服务器身份验证。</p>
        </template>
        <template v-else>
          <h4>strongSwan</h4><p>安装并信任 CA 后，按本机 swanctl 目录保存以下配置：</p><pre>{{ strongSwanConfig }}</pre>
        </template>
      </div>
    </div>
  </BaseModal>
</template>

<style scoped>
@reference "../style.css";
.icon-button { @apply rounded-lg p-2 text-slate-400 transition hover:bg-white hover:text-cyan-600 dark:hover:bg-slate-700 dark:hover:text-cyan-300; }
.secondary { @apply flex shrink-0 items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-600 hover:border-cyan-300 hover:text-cyan-700 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300; }
.guide { @apply space-y-2 leading-6 text-slate-600 dark:text-slate-300; }
.guide h4 { @apply font-semibold text-slate-900 dark:text-slate-100; }
.guide ol { @apply list-decimal space-y-1 pl-5; }
.guide pre { @apply overflow-x-auto whitespace-pre-wrap rounded-lg bg-slate-900 p-3 font-mono text-xs leading-5 text-slate-100; }
.guide code { @apply break-all rounded bg-slate-100 px-1 py-0.5 font-mono text-xs dark:bg-slate-700; }
</style>
