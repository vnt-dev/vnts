<script setup lang="ts">
import { Plus } from '@lucide/vue'
import { onMounted, onUnmounted, ref } from 'vue'
import { portMappingApi } from '@/api/modules'
import BaseModal from '@/components/BaseModal.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import { useToast } from '@/composables/useToast'
import type { PortMapping, PortMappingConfig } from '@/types'

const toast = useToast()
const mappings = ref<PortMapping[]>([])
const editor = ref<PortMappingConfig | null>(null)
const editId = ref<string>()
const deleteTarget = ref<PortMapping | null>(null)
const saving = ref(false)
const loading = ref(true)
const loadError = ref('')
const formError = ref('')
let generation = 0
let timer: ReturnType<typeof setInterval>

const input = 'w-full rounded-lg border border-slate-200 bg-white px-3 py-2 outline-none focus:border-blue-500 dark:border-slate-600 dark:bg-slate-900'
const primary = 'inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-50'
const secondary = 'rounded-lg px-3 py-2 text-sm font-medium hover:bg-slate-100 disabled:opacity-50 dark:hover:bg-slate-700'

function configOf(mapping: PortMapping): PortMappingConfig {
  const { protocol, listen_ip, listen_port, network_code, virtual_ip, lan_ip, target_port, enabled } = mapping
  return { protocol, listen_ip, listen_port, network_code, virtual_ip, lan_ip, target_port, enabled }
}

function errorText(error: unknown) {
  return error instanceof Error ? error.message : '操作失败'
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    mappings.value = await portMappingApi.list()
  } catch (error) {
    loadError.value = errorText(error)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void load()
  timer = setInterval(async () => {
    if (saving.value || loading.value || loadError.value) return
    const request = ++generation
    const result = await portMappingApi.poll()
    if (result && request === generation) mappings.value = result
  }, 5000)
})

onUnmounted(() => {
  clearInterval(timer)
  generation++
})

function openEditor(mapping?: PortMapping) {
  editId.value = mapping?.id
  formError.value = ''
  editor.value = mapping ? configOf(mapping) : {
    protocol: 'tcp',
    listen_ip: '0.0.0.0',
    listen_port: 0,
    network_code: '',
    virtual_ip: '',
    lan_ip: null,
    target_port: 0,
    enabled: true,
  }
}

async function mutate(action: () => Promise<PortMapping[]>) {
  if (saving.value) return
  generation++
  saving.value = true
  try {
    mappings.value = await action()
    return true
  } finally {
    saving.value = false
  }
}

async function save() {
  if (!editor.value) return
  const config = {
    ...editor.value,
    listen_ip: editor.value.listen_ip.trim() || '0.0.0.0',
    network_code: editor.value.network_code.trim(),
    virtual_ip: editor.value.virtual_ip.trim(),
    lan_ip: editor.value.lan_ip?.trim() || null,
  }
  const id = editId.value
  formError.value = ''
  try {
    if (await mutate(() => id ? portMappingApi.update(id, config) : portMappingApi.create(config))) {
      editor.value = null
    }
  } catch (error) {
    formError.value = errorText(error)
  }
}

async function setEnabled(mapping: PortMapping, enabled: boolean) {
  const config = configOf(mapping)
  config.enabled = enabled
  try {
    await mutate(() => portMappingApi.update(mapping.id, config))
  } catch (error) {
    toast.error(errorText(error))
  }
}

async function remove() {
  const id = deleteTarget.value?.id
  if (!id) return
  try {
    if (await mutate(() => portMappingApi.remove(id))) deleteTarget.value = null
  } catch (error) {
    toast.error(errorText(error))
  }
}
</script>

<template>
  <div class="space-y-5">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <p class="text-sm text-slate-500 dark:text-slate-400">目标客户端需要直连本服务端，并开启「允许服务端反代」。</p>
      <button :class="primary" :disabled="saving || loading || !!loadError" @click="openEditor()">
        <Plus :size="16" /> 新增映射
      </button>
    </div>

    <p v-if="loading" class="text-sm text-slate-500" role="status">正在加载端口映射…</p>
    <div v-else-if="loadError" class="flex items-center gap-2 text-sm text-red-600" role="alert">
      {{ loadError }}
      <button :class="secondary" @click="load">重试</button>
    </div>
    <p v-else-if="!mappings.length" class="rounded-xl border border-slate-200 px-5 py-8 text-center text-sm text-slate-500 dark:border-slate-700">暂无端口映射</p>

    <ul v-else class="grid gap-3 xl:grid-cols-2">
      <li v-for="mapping in mappings" :key="mapping.id" class="min-w-0 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <p class="font-mono font-semibold text-slate-900 dark:text-slate-100">
            {{ mapping.protocol.toUpperCase() }} {{ mapping.listen_ip }}:{{ mapping.listen_port }}
          </p>
          <span class="text-xs font-medium"
            :class="mapping.listening ? 'text-emerald-700 dark:text-emerald-400' : mapping.bind_error ? 'text-red-700 dark:text-red-400' : 'text-slate-500'">
            {{ mapping.listening ? '监听中' : mapping.bind_error ? '绑定失败' : mapping.enabled ? '未监听' : '已停用' }}
          </span>
        </div>
        <dl class="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
          <dt class="text-slate-500 dark:text-slate-400">网络编号</dt>
          <dd class="break-all">{{ mapping.network_code }}</dd>
          <dt class="text-slate-500 dark:text-slate-400">虚拟 IP</dt>
          <dd class="font-mono">{{ mapping.virtual_ip }}</dd>
          <dt class="text-slate-500 dark:text-slate-400">目标地址</dt>
          <dd class="font-mono">{{ mapping.lan_ip || '127.0.0.1' }}:{{ mapping.target_port }}</dd>
          <dt class="text-slate-500 dark:text-slate-400">目标状态</dt>
          <dd>{{ mapping.target_ready ? '直连且已授权' : '未直连或未授权' }}</dd>
        </dl>
        <p v-if="mapping.bind_error" class="mt-3 break-all text-sm text-red-700 dark:text-red-400">{{ mapping.bind_error }}</p>
        <div class="mt-4 flex flex-wrap justify-end gap-1">
          <button :class="secondary" :disabled="saving" @click="openEditor(mapping)">编辑</button>
          <button v-if="mapping.enabled && !mapping.listening" :class="secondary" :disabled="saving" @click="setEnabled(mapping, true)">重试监听</button>
          <button :class="secondary" :disabled="saving" @click="setEnabled(mapping, !mapping.enabled)">
            {{ mapping.enabled ? '停用' : '启用' }}
          </button>
          <button :class="secondary" class="text-red-600 dark:text-red-400" :disabled="saving" @click="deleteTarget = mapping">删除</button>
        </div>
      </li>
    </ul>

    <BaseModal :open="!!editor" :title="editId ? '编辑映射' : '新增映射'" @close="!saving && (editor = null)">
      <form v-if="editor" class="space-y-4 text-sm" @submit.prevent="save">
        <fieldset :disabled="saving" class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label class="space-y-1"><span>协议类型</span>
            <select v-model="editor.protocol" :class="input"><option value="tcp">TCP</option><option value="udp">UDP</option></select>
          </label>
          <label class="space-y-1"><span>监听端口</span>
            <input v-model.number="editor.listen_port" type="number" min="1" max="65535" required :class="input">
          </label>
          <label class="space-y-1"><span>监听 IPv4</span>
            <input v-model="editor.listen_ip" placeholder="0.0.0.0" :class="input">
          </label>
          <label class="space-y-1"><span>网络编号</span>
            <input v-model="editor.network_code" required :class="input">
          </label>
          <label class="space-y-1"><span>客户端虚拟 IPv4</span>
            <input v-model="editor.virtual_ip" placeholder="10.26.0.2" required :class="input">
          </label>
          <label class="space-y-1"><span>目标端口</span>
            <input v-model.number="editor.target_port" type="number" min="1" max="65535" required :class="input">
          </label>
          <label class="space-y-1 sm:col-span-2"><span>内网 IPv4（可选）</span>
            <input v-model="editor.lan_ip" placeholder="留空时使用客户端的 127.0.0.1" :class="input">
          </label>
          <label class="flex items-center gap-2"><input v-model="editor.enabled" type="checkbox"> 启用映射</label>
        </fieldset>
        <p v-if="formError" class="text-red-600 dark:text-red-400" role="alert">{{ formError }}</p>
        <div class="flex justify-end gap-2">
          <button type="button" :class="secondary" :disabled="saving" @click="editor = null">取消</button>
          <button type="submit" :class="primary" :disabled="saving">保存</button>
        </div>
      </form>
    </BaseModal>

    <ConfirmDialog :open="!!deleteTarget" :loading="saving"
      :message="`确定删除 ${deleteTarget?.protocol.toUpperCase() ?? ''} ${deleteTarget?.listen_ip ?? ''}:${deleteTarget?.listen_port ?? ''} 的映射？现有连接将断开。`"
      @confirm="remove" @close="!saving && (deleteTarget = null)"
    />
  </div>
</template>
