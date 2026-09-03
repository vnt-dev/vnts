<script setup lang="ts">
import { CheckCircle2, Download, LoaderCircle, Save, ShieldCheck } from '@lucide/vue'
import { computed, onMounted, reactive, ref } from 'vue'
import { ApiError } from '@/api/client'
import { settingsApi } from '@/api/modules'
import { useToast } from '@/composables/useToast'
import type { Ikev2ServiceInfo, UpdateIkev2ServicePayload } from '@/types'

const toast = useToast()
const loading = ref(false)
const saving = ref(false)
const saveError = ref('')
const info = ref<Ikev2ServiceInfo | null>(null)
const autoCertificate = ref(true)
const form = reactive({
  enabled: false,
  ikeBind: '0.0.0.0:500',
  nattBind: '0.0.0.0:4500',
  remoteId: '',
  publicIp: '',
  dns: '',
  cert: '',
  key: '',
})

const status = computed(() => {
  if (saving.value) return { text: '等待应用', cls: 'bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300' }
  if (saveError.value || info.value?.runtime_error) return { text: '启动失败', cls: 'bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300' }
  if (!info.value?.enabled) return { text: '未启用', cls: 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300' }
  if (info.value.runtime_active) return { text: '运行中', cls: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300' }
  return { text: '未运行', cls: 'bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300' }
})

const certificateExpiry = computed(() => info.value?.certificate_not_after
  ? new Date(info.value.certificate_not_after * 1000).toLocaleDateString()
  : '未知')
const usesNonstandardPorts = computed(() => {
  const port = (address: string) => Number(address.match(/:(\d+)$/)?.[1])
  return port(form.ikeBind.trim()) !== 500 || port(form.nattBind.trim()) !== 4500
})

function applyInfo(value: Ikev2ServiceInfo) {
  info.value = value
  form.enabled = value.enabled
  form.ikeBind = value.ike_bind
  form.nattBind = value.natt_bind
  form.remoteId = value.remote_id
  form.publicIp = value.public_ip ?? ''
  form.dns = value.dns.join(', ')
  form.cert = value.cert ?? ''
  form.key = value.key ?? ''
  autoCertificate.value = !value.configured
    || value.certificate_managed
    || (!value.cert && !value.key)
  saveError.value = value.runtime_error ?? ''
}

async function load() {
  loading.value = true
  try {
    applyInfo(await settingsApi.getIkev2())
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '加载 IKEv2 基础配置失败')
  } finally {
    loading.value = false
  }
}

function useCurrentHost() {
  if (window.location.hostname) form.remoteId = window.location.hostname
}

function validate() {
  if (form.enabled && !form.remoteId.trim()) {
    toast.error('启用服务前必须填写 Remote ID')
    return false
  }
  if (!autoCertificate.value && (!form.cert.trim() || !form.key.trim())) {
    toast.error('自定义证书模式必须同时填写 cert 和 key 路径')
    return false
  }
  return true
}

async function save() {
  if (!validate() || saving.value) return
  const payload: UpdateIkev2ServicePayload = {
    enabled: form.enabled,
    ike_bind: form.ikeBind.trim(),
    natt_bind: form.nattBind.trim(),
    remote_id: form.remoteId.trim(),
    public_ip: form.publicIp.trim() || undefined,
    dns: form.dns.split(/[,，\s]+/).map((value) => value.trim()).filter(Boolean),
    cert: autoCertificate.value ? undefined : form.cert.trim(),
    key: autoCertificate.value ? undefined : form.key.trim(),
  }
  saving.value = true
  saveError.value = ''
  try {
    applyInfo(await settingsApi.updateIkev2(payload))
    toast.success(form.enabled ? 'IKEv2/IPsec 基础配置已保存并生效' : 'IKEv2/IPsec 服务已停用，配置已保留')
  } catch (error) {
    saveError.value = error instanceof ApiError ? error.message : '保存 IKEv2 基础配置失败'
    toast.error(saveError.value)
  } finally {
    saving.value = false
  }
}

async function downloadCa(format: 'der' | 'pem') {
  try {
    await settingsApi.downloadIkev2Ca(format)
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '下载 CA 证书失败')
  }
}

onMounted(load)
</script>

<template>
  <section class="mt-6 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-800">
    <div class="flex flex-col gap-3 border-b border-slate-100 px-5 py-4 dark:border-slate-700 sm:flex-row sm:items-center sm:justify-between">
      <div class="flex items-start gap-3">
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-cyan-50 text-cyan-600 dark:bg-cyan-500/10 dark:text-cyan-300"><ShieldCheck :size="21" /></div>
        <div><div class="flex items-center gap-2"><h3 class="font-semibold text-slate-900 dark:text-slate-100">IKEv2/IPsec 基础配置</h3><span v-if="info" class="rounded-full px-2.5 py-1 text-xs font-semibold" :class="status.cls">{{ status.text }}</span></div><p class="mt-0.5 text-sm text-slate-500 dark:text-slate-400">全局共享设置；IKEv2 用户名和密码在网络详情的设备列表中管理</p></div>
      </div>
      <label v-if="info" class="flex items-center gap-2 text-sm font-medium"><span>启用服务</span><input v-model="form.enabled" type="checkbox" class="h-5 w-5 accent-cyan-600" /></label>
    </div>
    <div v-if="loading" class="flex justify-center py-20"><LoaderCircle :size="28" class="animate-spin text-cyan-500" /></div>
    <div v-else-if="info" class="space-y-5 p-5 sm:p-6">
      <p v-if="saveError || info.runtime_error" class="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-600 dark:bg-red-500/10 dark:text-red-300">{{ saveError || info.runtime_error }}</p>
      <div class="rounded-lg bg-amber-50 px-3.5 py-3 text-sm leading-6 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300">修改监听地址、Remote ID 或证书会断开现有 IKEv2 会话并要求客户端重连。保存失败时自动恢复原配置和服务。</div>
      <div v-if="usesNonstandardPorts" class="rounded-lg border border-orange-300 bg-orange-50 px-3.5 py-3 text-sm font-medium leading-6 text-orange-700 dark:border-orange-500/40 dark:bg-orange-500/10 dark:text-orange-300">当前使用了非标准 IKEv2 端口。Windows、macOS、iOS、Android 等系统内置客户端通常不能指定非 UDP 500/4500 端口，可能无法连接；除非使用明确支持自定义端口的客户端，否则建议保持默认端口。</div>
      <div class="grid gap-5 lg:grid-cols-2">
        <div><label class="label">IKE 监听地址</label><input v-model="form.ikeBind" class="field" placeholder="0.0.0.0:500" /><p class="hint">初始协商监听地址，通常保持 0.0.0.0:500；防火墙需放行 UDP 500。</p></div>
        <div><label class="label">NAT-T 监听地址</label><input v-model="form.nattBind" class="field" placeholder="0.0.0.0:4500" /><p class="hint">NAT-T/ESP 数据监听地址，通常保持 0.0.0.0:4500；需放行 UDP 4500。</p></div>
        <div><label class="label">Remote ID</label><div class="mt-1.5 flex gap-2"><input v-model="form.remoteId" class="field mt-0" placeholder="vpn.example.com 或 203.0.113.10" /><button type="button" class="secondary" @click="useCurrentHost">当前地址</button></div><p class="hint">客户端验证的服务器身份，填写实际可访问的域名或 IPv4。</p></div>
        <div><label class="label">公网 IP（可选）</label><input v-model="form.publicIp" class="field" placeholder="203.0.113.10" /><p class="hint">服务器位于 NAT 后时填写公网 IPv4；公网直连通常留空。</p></div>
        <div class="lg:col-span-2"><label class="label">客户端 DNS（可选）</label><input v-model="form.dns" class="field" placeholder="1.1.1.1, 8.8.8.8" /><p class="hint">下发给 VPN 客户端的 IPv4 DNS，多个值用逗号或空格分隔。</p></div>
        <div class="lg:col-span-2 rounded-lg border border-slate-200 p-4 dark:border-slate-700">
          <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div><div class="label">服务器证书</div><p class="hint mt-1">推荐自动管理：生成本地 CA，并签发匹配 Remote ID 的 RSA-2048 证书。</p></div><label class="flex items-center gap-2 text-sm"><input v-model="autoCertificate" type="checkbox" class="accent-cyan-600" />自动生成和续签</label></div>
          <div v-if="autoCertificate" class="mt-3 flex flex-wrap items-center gap-2 rounded-lg bg-cyan-50 px-3 py-2 text-xs text-cyan-700 dark:bg-cyan-500/10 dark:text-cyan-300"><CheckCircle2 :size="15" />cert/key 留空时自动生成<span v-if="info.certificate_managed">；有效期至 {{ certificateExpiry }}</span><button v-if="info.ca_download_available" type="button" class="ml-auto secondary" @click="downloadCa('der')"><Download :size="14" />下载 CA (.cer)</button><button v-if="info.ca_download_available" type="button" class="secondary" @click="downloadCa('pem')">PEM</button></div>
          <div v-else class="mt-3 grid gap-4 lg:grid-cols-2"><div><label class="label">cert 证书链路径</label><input v-model="form.cert" class="field" placeholder="/etc/vnts/ikev2-cert.pem" /><p class="hint">PEM 证书链，首张证书 SAN 必须匹配 Remote ID。</p></div><div><label class="label">key 私钥路径</label><input v-model="form.key" class="field" placeholder="/etc/vnts/ikev2-key.pem" /><p class="hint">匹配证书的 RSA 或 ECDSA P-256 PKCS#8 私钥路径。</p></div><p v-if="info.certificate_configured && !info.certificate_managed" class="text-xs text-slate-500 lg:col-span-2">当前自定义证书有效期至 {{ certificateExpiry }}；私有 CA 需自行安装到客户端。</p></div>
        </div>
      </div>
      <div class="flex justify-end border-t border-slate-100 pt-5 dark:border-slate-700"><button type="button" class="primary" :disabled="saving" @click="save"><LoaderCircle v-if="saving" :size="15" class="animate-spin" /><Save v-else :size="15" />{{ saving ? '保存并应用中...' : '保存并应用' }}</button></div>
    </div>
  </section>
</template>

<style scoped>
@reference "../style.css";
.label { @apply text-sm font-medium text-slate-700 dark:text-slate-300; }
.field { @apply mt-1.5 w-full rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm text-slate-800 placeholder:text-slate-400 outline-none transition focus:border-cyan-400 focus:ring-2 focus:ring-cyan-100 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200 dark:focus:border-cyan-500 dark:focus:ring-cyan-500/20; }
.hint { @apply mt-1.5 text-xs leading-5 text-slate-400 dark:text-slate-500; }
.secondary { @apply inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg border border-slate-200 px-3 py-2 text-xs font-semibold text-slate-600 transition hover:bg-slate-50 disabled:opacity-40 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-700; }
.primary { @apply inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-700 disabled:opacity-50; }
</style>
