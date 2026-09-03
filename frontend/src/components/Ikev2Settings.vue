<script setup lang="ts">
import { Clipboard, Download, Eye, EyeOff, Info, KeyRound, LoaderCircle, Plus, RefreshCw, Save, Settings, ShieldCheck, Trash2 } from '@lucide/vue'
import { computed, reactive, ref, watch } from 'vue'
import { ApiError } from '@/api/client'
import { networkApi } from '@/api/modules'
import { useToast } from '@/composables/useToast'
import type { NetworkIkev2Info, UpdateNetworkIkev2Payload } from '@/types'

const props = defineProps<{ networkCode: string }>()
const toast = useToast()
const loading = ref(false)
const saving = ref(false)
const revealing = ref(false)
const saveError = ref('')
const info = ref<NetworkIkev2Info | null>(null)
const showPsk = ref(false)
const guidePlatform = ref<'windows' | 'apple' | 'android' | 'strongswan'>('windows')

interface EapFormUser {
  id: string
  username: string
  password: string
  existing: boolean
  visible: boolean
}

const form = reactive({
  networkEnabled: false,
  psk: '',
  eapUsers: [] as EapFormUser[],
})

const status = computed(() => {
  if (saving.value) return { text: '等待应用', cls: 'bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300' }
  if (saveError.value || info.value?.service.runtime_error) return { text: '启动失败', cls: 'bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300' }
  if (!info.value?.service.enabled) return { text: '未启用', cls: 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300' }
  if (info.value.service.runtime_active) return { text: '运行中', cls: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300' }
  return { text: '未运行', cls: 'bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300' }
})

const eapAvailable = computed(() => form.eapUsers.length > 0)
const pskAvailable = computed(() => Boolean(form.psk) || Boolean(info.value?.network.psk_configured))
const serverAddress = computed(() => info.value?.service.public_ip || info.value?.service.remote_id || '尚未填写')
const remoteIdentity = computed(() => info.value?.service.remote_id || '尚未填写')
const platforms = computed(() => [
  ...(eapAvailable.value ? [{ id: 'windows' as const, label: 'Windows 11' }] : []),
  { id: 'apple' as const, label: 'macOS / iOS' },
  { id: 'android' as const, label: 'Android' },
  { id: 'strongswan' as const, label: 'strongSwan' },
])

watch(platforms, (items) => {
  if (!items.some((item) => item.id === guidePlatform.value)) guidePlatform.value = items[0]?.id ?? 'apple'
})

function applyInfo(value: NetworkIkev2Info) {
  info.value = value
  form.networkEnabled = value.network.enabled
  form.psk = ''
  form.eapUsers = value.network.eap_users.map((username) => ({
    id: crypto.randomUUID(),
    username,
    password: '',
    existing: true,
    visible: false,
  }))
  showPsk.value = false
  saveError.value = value.service.runtime_error ?? ''
}

async function load() {
  loading.value = true
  try {
    applyInfo(await networkApi.getIkev2(props.networkCode))
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '加载 IKEv2 配置失败')
  } finally {
    loading.value = false
  }
}

watch(() => props.networkCode, load, { immediate: true })

function randomSecret(length = 32) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_'
  const limit = Math.floor(256 / alphabet.length) * alphabet.length
  let value = ''
  while (value.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length - value.length + 8))
    for (const byte of bytes) {
      if (byte < limit) value += alphabet[byte % alphabet.length]
      if (value.length === length) break
    }
  }
  return value
}

function generatePsk() {
  form.psk = randomSecret(40)
  showPsk.value = true
}

function randomUsername() {
  return `user-${randomSecret(10).toLowerCase()}`
}

function addEapUser() {
  form.eapUsers.push({ id: crypto.randomUUID(), username: randomUsername(), password: randomSecret(24), existing: false, visible: true })
}

function removeEapUser(index: number) {
  form.eapUsers.splice(index, 1)
}

function generateEapPassword(user: EapFormUser) {
  user.password = randomSecret(24)
  user.visible = true
}

function generateEapUsername(user: EapFormUser) {
  user.username = randomUsername()
}

async function revealSecrets() {
  revealing.value = true
  try {
    const secrets = await networkApi.getIkev2Secrets(props.networkCode)
    if (secrets.psk) {
      form.psk = secrets.psk
      showPsk.value = true
    }
    for (const user of form.eapUsers) {
      const password = secrets.eap_users[user.username]
      if (password) {
        user.password = password
        user.visible = true
      }
    }
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '读取凭据失败')
  } finally {
    revealing.value = false
  }
}

async function copy(value: string) {
  if (!value) return
  await navigator.clipboard.writeText(value)
  toast.success('已复制到剪贴板')
}

function validate(): boolean {
  const usernames = form.eapUsers.map((user) => user.username.trim())
  if (usernames.some((value) => !value) || new Set(usernames).size !== usernames.length) {
    toast.error('EAP 用户名不能为空或重复')
    return false
  }
  if (form.eapUsers.some((user) => !user.existing && !user.password)) {
    toast.error('新增 EAP 用户必须填写密码')
    return false
  }
  if (form.networkEnabled && !eapAvailable.value) {
    toast.error('启用当前网络时必须至少配置一个 EAP-MSCHAPv2 用户')
    return false
  }
  return true
}

async function save() {
  if (!validate() || saving.value) return
  saveError.value = ''
  const payload: UpdateNetworkIkev2Payload = {
    enabled: form.networkEnabled,
    eap_users: form.eapUsers.map((user) => ({
      username: user.username.trim(),
      ...(user.password ? { password: user.password } : {}),
    })),
  }
  if (form.psk) payload.psk = form.psk
  saving.value = true
  try {
    applyInfo(await networkApi.updateIkev2(props.networkCode, payload))
    toast.success('当前网络的 IKEv2 认证已保存并生效')
  } catch (error) {
    saveError.value = error instanceof ApiError ? error.message : '保存 IKEv2 配置失败'
    toast.error(saveError.value)
  } finally {
    saving.value = false
  }
}

async function downloadCa(format: 'der' | 'pem') {
  try {
    await networkApi.downloadCaCertificate(format)
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '下载 CA 证书失败')
  }
}

const windowsCommand = computed(() => `Set-VpnConnectionIPsecConfiguration -ConnectionName "VNT-${props.networkCode}" -EncryptionMethod GCMAES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -CipherTransformConstants GCMAES256 -AuthenticationTransformConstants GCMAES256 -PfsGroup None -Force`)
const strongSwanAuth = computed(() => eapAvailable.value
  ? 'local { auth = eap-mschapv2; eap_id = YOUR_USERNAME }\n    remote { auth = pubkey; id = ' + remoteIdentity.value + ' }'
  : 'local { auth = psk; id = YOUR_STABLE_LOCAL_ID }\n    remote { auth = psk; id = ' + remoteIdentity.value + ' }')
const strongSwanSecrets = computed(() => eapAvailable.value
  ? 'eap-vnt { id = YOUR_USERNAME; secret = "YOUR_PASSWORD" }'
  : 'ike-vnt { id = YOUR_STABLE_LOCAL_ID; secret = "YOUR_PSK" }')
const strongSwanConfig = computed(() => `connections {
  vnt-${props.networkCode} {
    remote_addrs = ${serverAddress.value}
    vips = 0.0.0.0
    proposals = aes256gcm16-prfsha256-modp2048
    children { vnt { remote_ts = ${info.value?.network_net ?? 'VNT_SUBNET'} } }
    ${strongSwanAuth.value}
  }
}
secrets {
  ${strongSwanSecrets.value}
}`)
</script>

<template>
  <div v-if="loading" class="flex justify-center rounded-xl bg-white py-24 dark:bg-slate-800">
    <LoaderCircle :size="28" class="animate-spin text-cyan-500" />
  </div>
  <div v-else-if="info" class="space-y-5">
    <section class="rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-800">
      <div class="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
        <div class="flex items-start gap-3">
          <div class="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-cyan-50 text-cyan-600 dark:bg-cyan-500/10 dark:text-cyan-300"><ShieldCheck :size="23" /></div>
          <div>
            <div class="flex items-center gap-2"><h3 class="font-bold text-slate-900 dark:text-slate-100">IKEv2/IPsec 接入服务</h3><span class="rounded-full px-2.5 py-1 text-xs font-semibold" :class="status.cls">{{ status.text }}</span></div>
            <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">让手机和系统原生 VPN 客户端接入当前 VNT 网络。</p>
            <p v-if="saveError || info.service.runtime_error" class="mt-2 text-sm text-red-600 dark:text-red-400">{{ saveError || info.service.runtime_error }}</p>
          </div>
        </div>
        <RouterLink :to="{ name: 'settings' }" class="secondary"><Settings :size="14" />前往系统设置</RouterLink>
      </div>
    </section>

    <section class="rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-800">
      <div class="flex flex-col gap-3 border-b border-slate-100 px-5 py-4 dark:border-slate-700 sm:flex-row sm:items-center sm:justify-between">
        <div><h3 class="font-semibold text-slate-900 dark:text-slate-100">当前网络认证 · {{ networkCode }}</h3><p class="mt-1 text-sm text-slate-500 dark:text-slate-400">只影响当前网络；启用时必须至少有一个 EAP-MSCHAPv2 用户，PSK 为可选项。</p></div>
        <label class="flex items-center gap-2 text-sm font-medium"><input v-model="form.networkEnabled" type="checkbox" class="h-4 w-4 accent-cyan-600" />允许接入当前网络</label>
      </div>
      <div v-if="form.networkEnabled" class="space-y-6 p-5">
        <div>
          <div class="mb-2 flex items-center justify-between"><div><div class="text-sm font-medium text-slate-700 dark:text-slate-300">预共享密钥（PSK）</div><p class="hint mt-0.5">适合 Android、Apple 和 strongSwan；不同网络的 PSK 不能重复。</p></div><button v-if="info.network.psk_configured || info.network.eap_users.length" type="button" class="secondary" :disabled="revealing" @click="revealSecrets"><Eye :size="14" />查看已保存凭据</button></div>
          <div class="flex gap-2"><div class="relative min-w-0 flex-1"><input v-model="form.psk" :type="showPsk ? 'text' : 'password'" class="field mt-0 pr-10" :placeholder="info.network.psk_configured ? '留空保留原 PSK' : '输入或自动生成 PSK'" /><button type="button" class="absolute right-3 top-1/2 flex -translate-y-1/2 items-center text-slate-400 hover:text-cyan-600" title="显示或隐藏密码" @click="showPsk = !showPsk"><EyeOff v-if="showPsk" :size="16" /><Eye v-else :size="16" /></button></div><button type="button" class="secondary" @click="generatePsk"><RefreshCw :size="14" />生成</button><button type="button" class="secondary" :disabled="!form.psk" @click="copy(form.psk)"><Clipboard :size="14" /></button></div>
        </div>
        <div>
          <div class="mb-2 flex items-center justify-between"><div><div class="text-sm font-medium text-slate-700 dark:text-slate-300">EAP-MSCHAPv2 用户</div><p class="hint mt-0.5">Windows 原生客户端必须使用此方式，用户名在所有网络中不能重复。</p></div><button type="button" class="secondary" @click="addEapUser"><Plus :size="14" />添加用户</button></div>
          <div v-if="form.eapUsers.length" class="space-y-2"><div v-for="(user, index) in form.eapUsers" :key="user.id" class="grid gap-2 sm:grid-cols-[minmax(8rem,1fr)_auto_minmax(8rem,1fr)_auto_auto_auto]"><input v-model="user.username" class="field mt-0" placeholder="用户名" /><button type="button" class="secondary" title="自动生成用户名" @click="generateEapUsername(user)"><RefreshCw :size="14" /></button><div class="relative min-w-0"><input v-model="user.password" :type="user.visible ? 'text' : 'password'" class="field mt-0 pr-10" :placeholder="user.existing ? '留空保留密码' : '密码'" /><button type="button" class="absolute right-3 top-1/2 flex -translate-y-1/2 items-center text-slate-400 hover:text-cyan-600" title="显示或隐藏密码" @click="user.visible = !user.visible"><EyeOff v-if="user.visible" :size="16" /><Eye v-else :size="16" /></button></div><button type="button" class="secondary" title="生成新密码" @click="generateEapPassword(user)"><RefreshCw :size="14" /></button><button type="button" class="secondary" title="复制密码" :disabled="!user.password" @click="copy(user.password)"><Clipboard :size="14" /></button><button type="button" class="danger" title="删除用户" @click="removeEapUser(index)"><Trash2 :size="14" /></button></div></div>
          <div v-else class="rounded-lg border border-dashed border-slate-200 py-6 text-center text-sm text-slate-400 dark:border-slate-700">尚未配置 EAP 用户</div>
        </div>
      </div>
    </section>

    <div class="sticky bottom-4 z-10 flex items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white/95 p-4 shadow-lg backdrop-blur dark:border-slate-700 dark:bg-slate-800/95"><div class="flex items-start gap-2 text-xs text-slate-500 dark:text-slate-400"><Info :size="16" class="shrink-0 text-amber-500" /><span>这里只保存当前网络的认证数据；服务监听、Remote ID 和证书请到系统设置修改。</span></div><button type="button" class="primary" :disabled="saving" @click="save"><LoaderCircle v-if="saving" :size="15" class="animate-spin" /><Save v-else :size="15" />{{ saving ? '保存并应用中...' : '保存并应用' }}</button></div>

    <section v-if="info.service.enabled && info.network.enabled" class="rounded-xl border border-cyan-200 bg-white shadow-sm dark:border-cyan-500/30 dark:bg-slate-800">
      <div class="border-b border-slate-100 px-5 py-4 dark:border-slate-700"><h3 class="font-semibold text-slate-900 dark:text-slate-100">客户端接入指南</h3><p class="mt-1 text-sm text-slate-500 dark:text-slate-400">IPv4 分流 VPN：只访问 {{ info.network_net }}，不会接管客户端的默认互联网流量。</p></div>
      <div class="space-y-5 p-5">
        <div class="grid gap-3 rounded-lg bg-slate-50 p-4 text-sm dark:bg-slate-900/50 sm:grid-cols-2 lg:grid-cols-4"><div><span class="text-slate-400">服务器地址</span><div class="mt-1 flex items-center gap-2 font-mono font-semibold">{{ serverAddress }}<button type="button" title="复制" class="text-slate-400 hover:text-cyan-600" @click="copy(serverAddress)"><Clipboard :size="13" /></button></div></div><div><span class="text-slate-400">Remote ID</span><div class="mt-1 flex items-center gap-2 font-mono font-semibold">{{ remoteIdentity }}<button type="button" title="复制" class="text-slate-400 hover:text-cyan-600" @click="copy(remoteIdentity)"><Clipboard :size="13" /></button></div></div><div><span class="text-slate-400">目标网段</span><div class="mt-1 flex items-center gap-2 font-mono font-semibold">{{ info.network_net }}<button type="button" title="复制" class="text-slate-400 hover:text-cyan-600" @click="copy(info.network_net)"><Clipboard :size="13" /></button></div></div><div><span class="text-slate-400">开放端口</span><div class="mt-1 font-mono font-semibold">UDP 500 / 4500</div></div></div>
        <div class="flex flex-wrap gap-2 text-xs"><span class="text-slate-400">当前认证：</span><span v-if="eapAvailable" class="rounded-full bg-violet-50 px-2 py-1 text-violet-700 dark:bg-violet-500/10 dark:text-violet-300">EAP-MSCHAPv2</span><span v-if="pskAvailable" class="rounded-full bg-amber-50 px-2 py-1 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300">PSK</span></div>
        <div class="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm leading-6 text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300">若服务器位于路由器后，请将 UDP 500、4500 转发到本机。需要与该 VPN 客户端通信的 VNT 客户端必须增加 <code>--allow-ikev2</code> 或配置 <code>allow_ikev2 = true</code>。PSK 客户端还必须填写一个非空且稳定的本地 ID，用来保持设备身份和虚拟 IP。</div>
        <div v-if="info.service.ca_download_available" class="flex flex-wrap items-center gap-3 rounded-lg border border-cyan-200 p-3 text-sm dark:border-cyan-500/30"><KeyRound :size="18" class="text-cyan-600" /><span class="flex-1">EAP 客户端连接前必须安装并信任自动生成的 VNT IKEv2 CA。</span><button type="button" class="secondary" @click="downloadCa('der')"><Download :size="14" />下载 CA 证书</button></div>
        <div class="flex flex-wrap gap-2"><button v-for="item in platforms" :key="item.id" type="button" class="rounded-lg px-3 py-2 text-sm font-medium" :class="guidePlatform === item.id ? 'bg-cyan-600 text-white' : 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300'" @click="guidePlatform = item.id">{{ item.label }}</button></div>
        <div v-if="guidePlatform === 'windows'" class="guide"><h4>Windows 11（EAP-MSCHAPv2）</h4><ol><li v-if="info.service.ca_download_available">下载 CA 证书，导入“本地计算机 → 受信任的根证书颁发机构”。</li><li v-else>如果自定义服务器证书由私有 CA 签发，请先将该 CA 导入“本地计算机 → 受信任的根证书颁发机构”。</li><li>设置 → 网络和 Internet → VPN → 添加 VPN；连接名称填写 <code>VNT-{{ networkCode }}</code>，类型选择 IKEv2，服务器填写 <code>{{ serverAddress }}</code>。</li><li>登录信息选择“用户名和密码”，使用上方 EAP 用户。</li><li>用管理员 PowerShell 执行下列命令，使算法与服务端一致：</li></ol><pre>{{ windowsCommand }}</pre></div>
        <div v-else-if="guidePlatform === 'apple'" class="guide"><h4>macOS / iOS</h4><ol><li v-if="info.service.ca_download_available && eapAvailable">安装下载的 CA，并在证书信任设置中启用完全信任。</li><li>新增 IKEv2 VPN：服务器填写 <code>{{ serverAddress }}</code>，Remote ID 填写 <code>{{ remoteIdentity }}</code>。</li><li v-if="eapAvailable">用户名认证：Local ID 留空，填写已配置的 EAP 用户名和密码。</li><li v-if="pskAvailable">共享密钥认证：填写当前网络 PSK，并设置一个非空且稳定的 Local ID。</li></ol></div>
        <div v-else-if="guidePlatform === 'android'" class="guide"><h4>Android</h4><ol><li>设置 → VPN → 添加 VPN，类型选择“IKEv2/IPSec MSCHAPv2”或“IKEv2/IPSec PSK”。</li><li>服务器地址和服务器标识均填写 <code>{{ serverAddress }}</code>。</li><li v-if="eapAvailable">MSCHAPv2 使用 EAP 用户名/密码，并选择已安装的 CA 证书。</li><li v-if="pskAvailable">PSK 类型填写当前网络的预共享密钥。</li></ol><p>不同厂商的菜单名称可能略有差异。</p></div>
        <div v-else class="guide"><h4>strongSwan（{{ eapAvailable ? 'EAP-MSCHAPv2' : 'PSK' }} 示例）</h4><p>将以下内容按本机 swanctl 目录调整，并把占位符替换为当前网络凭据；EAP 模式还需安装并信任 CA。</p><pre>{{ strongSwanConfig }}</pre></div>
      </div>
    </section>
  </div>
</template>

<style scoped>
@reference "../style.css";
.field { @apply mt-1.5 w-full rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm text-slate-800 placeholder:text-slate-400 outline-none transition focus:border-cyan-400 focus:ring-2 focus:ring-cyan-100 disabled:bg-slate-50 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200 dark:focus:border-cyan-500 dark:focus:ring-cyan-500/20; }
.hint { @apply mt-1.5 text-xs leading-5 text-slate-400 dark:text-slate-500; }
.secondary { @apply inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg border border-slate-200 px-3 py-2 text-xs font-semibold text-slate-600 transition hover:bg-slate-50 disabled:opacity-40 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-700; }
.danger { @apply inline-flex items-center justify-center rounded-lg px-3 py-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10; }
.primary { @apply inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-700 disabled:opacity-50; }
.guide { @apply space-y-3 rounded-lg border border-slate-200 p-4 text-sm leading-6 text-slate-600 dark:border-slate-700 dark:text-slate-300; }
.guide h4 { @apply font-semibold text-slate-900 dark:text-slate-100; }
.guide ol { @apply list-decimal space-y-1 pl-5; }
.guide code { @apply rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs dark:bg-slate-700; }
.guide pre { @apply overflow-x-auto whitespace-pre-wrap rounded-lg bg-slate-900 p-3 font-mono text-xs leading-5 text-slate-100; }
</style>
