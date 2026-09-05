<script setup lang="ts">
import { Info, LoaderCircle, Plus, RotateCcw, Save, ShieldCheck, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { ApiError } from '@/api/client'
import { networkApi, settingsApi } from '@/api/modules'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import Ikev2ServiceSettings from '@/components/Ikev2ServiceSettings.vue'
import { useToast } from '@/composables/useToast'

const toast = useToast()
const loading = ref(false)
const saving = ref(false)
const confirmClearOpen = ref(false)
const savedCodes = ref<string[]>([])
const codes = ref<string[]>([])
const existingCodes = ref<string[]>([])
const input = ref('')

const hasChanges = computed(() => {
  if (codes.value.length !== savedCodes.value.length) return true
  const saved = new Set(savedCodes.value)
  return codes.value.some((code) => !saved.has(code))
})

const availableSuggestions = computed(() => {
  const selected = new Set(codes.value)
  const query = input.value.trim().toLowerCase()
  return existingCodes.value.filter(
    (code) => !selected.has(code) && (!query || code.toLowerCase().includes(query)),
  )
})

const statusText = computed(() =>
  codes.value.length === 0 ? '未启用限制' : `已允许 ${codes.value.length} 个网络编码`,
)

async function loadSettings() {
  loading.value = true
  try {
    const [settings, networkCodes] = await Promise.all([
      settingsApi.getNetworkWhitelist(),
      networkApi.codes(),
    ])
    savedCodes.value = [...settings.network_codes]
    codes.value = [...settings.network_codes]
    existingCodes.value = [...networkCodes].sort()
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '加载白名单设置失败')
  } finally {
    loading.value = false
  }
}

function addCode(rawCode: string) {
  const code = rawCode.trim()
  if (!code) return
  if (new TextEncoder().encode(code).length > 32) {
    toast.error(`网络编码“${code}”超过 32 字节`)
    return
  }
  if (!codes.value.includes(code)) codes.value.push(code)
}

function addTokens(raw: string) {
  raw.split(/[,，\n\r]+/).forEach(addCode)
  input.value = ''
}

function commitInput() {
  addTokens(input.value)
}

function handleKeydown(event: KeyboardEvent) {
  if (event.key !== 'Enter' && event.key !== ',' && event.key !== '，') return
  event.preventDefault()
  commitInput()
}

function handlePaste(event: ClipboardEvent) {
  const text = event.clipboardData?.getData('text') ?? ''
  if (!/[,，\n\r]/.test(text)) return
  event.preventDefault()
  addTokens(text)
}

function removeCode(code: string) {
  codes.value = codes.value.filter((item) => item !== code)
}

function resetChanges() {
  codes.value = [...savedCodes.value]
  input.value = ''
}

function requestSave() {
  commitInput()
  if (!hasChanges.value || saving.value) return
  if (savedCodes.value.length > 0 && codes.value.length === 0) {
    confirmClearOpen.value = true
    return
  }
  void saveSettings()
}

async function saveSettings() {
  if (saving.value) return
  saving.value = true
  try {
    const settings = await settingsApi.updateNetworkWhitelist({
      network_codes: [...codes.value],
    })
    savedCodes.value = [...settings.network_codes]
    codes.value = [...settings.network_codes]
    confirmClearOpen.value = false
    toast.success('网络编码白名单已保存')
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '保存白名单失败')
  } finally {
    saving.value = false
  }
}

onMounted(loadSettings)
</script>

<template>
  <div class="mx-auto max-w-4xl">
    <div class="mb-6">
      <h2 class="text-xl font-bold text-slate-900 dark:text-slate-100">系统设置</h2>
      <p class="mt-0.5 text-sm text-slate-400 dark:text-slate-500">管理当前服务实例的运行配置</p>
    </div>

    <div class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-800">
      <div class="flex flex-col gap-3 border-b border-slate-100 px-5 py-4 dark:border-slate-700 sm:flex-row sm:items-center sm:justify-between">
        <div class="flex items-start gap-3">
          <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-blue-50 text-blue-600 dark:bg-blue-500/10 dark:text-blue-400">
            <ShieldCheck :size="21" />
          </div>
          <div>
            <h3 class="font-semibold text-slate-900 dark:text-slate-100">网络编码白名单</h3>
            <p class="mt-0.5 text-sm text-slate-500 dark:text-slate-400">限制允许连接到本服务的网络编码</p>
          </div>
        </div>
        <span
          class="w-fit rounded-full px-2.5 py-1 text-xs font-semibold"
          :class="codes.length === 0
            ? 'bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400'
            : 'bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400'"
        >
          {{ statusText }}
        </span>
      </div>

      <div v-if="loading" class="flex justify-center py-20">
        <LoaderCircle :size="28" class="animate-spin text-blue-500" />
      </div>

      <div v-else class="space-y-5 p-5 sm:p-6">
        <div class="flex gap-2 rounded-lg bg-blue-50 px-3.5 py-3 text-sm leading-6 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300">
          <Info :size="18" class="mt-0.5 shrink-0" />
          <p>
            白名单为空时允许任意网络编码。保存后立即限制新连接和重连，不会断开当前在线设备。
          </p>
        </div>

        <div>
          <label for="whitelist-code" class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">
            添加网络编码
          </label>
          <div class="flex gap-2">
            <input
              id="whitelist-code"
              v-model="input"
              type="text"
              list="network-code-suggestions"
              maxlength="32"
              class="min-w-0 flex-1 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm text-slate-800 placeholder:text-slate-400 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200 dark:placeholder:text-slate-500 dark:focus:border-blue-500 dark:focus:ring-blue-500/20"
              placeholder="输入编码后按 Enter，可粘贴逗号或换行分隔的多个编码"
              @keydown="handleKeydown"
              @paste="handlePaste"
            />
            <datalist id="network-code-suggestions">
              <option v-for="code in availableSuggestions" :key="code" :value="code" />
            </datalist>
            <button
              type="button"
              class="flex shrink-0 items-center gap-1.5 rounded-lg border border-slate-200 px-3.5 py-2 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700"
              @click="commitInput"
            >
              <Plus :size="16" />
              添加
            </button>
          </div>
          <p class="mt-1.5 text-xs text-slate-400 dark:text-slate-500">编码不能有首尾空格，UTF-8 长度最多 32 字节</p>
        </div>

        <div>
          <div class="mb-2 flex items-center justify-between">
            <span class="text-sm font-medium text-slate-700 dark:text-slate-300">已允许的网络编码</span>
            <span v-if="hasChanges" class="text-xs font-medium text-amber-600 dark:text-amber-400">有未保存的修改</span>
          </div>
          <div
            v-if="codes.length === 0"
            class="rounded-lg border border-dashed border-amber-300 bg-amber-50/50 px-4 py-8 text-center text-sm text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/5 dark:text-amber-400"
          >
            当前没有白名单限制，所有网络编码均可连接
          </div>
          <div v-else class="flex min-h-20 flex-wrap content-start gap-2 rounded-lg border border-slate-200 bg-slate-50/60 p-3 dark:border-slate-600 dark:bg-slate-900/40">
            <span
              v-for="code in codes"
              :key="code"
              class="inline-flex h-8 items-center gap-1.5 rounded-lg border border-blue-200 bg-blue-50 px-2.5 text-sm font-medium text-blue-700 dark:border-blue-500/30 dark:bg-blue-500/10 dark:text-blue-300"
            >
              {{ code }}
              <button
                type="button"
                class="rounded p-0.5 transition hover:bg-blue-100 hover:text-blue-900 dark:hover:bg-blue-500/20 dark:hover:text-blue-100"
                :aria-label="`移除 ${code}`"
                @click="removeCode(code)"
              >
                <X :size="13" />
              </button>
            </span>
          </div>
        </div>

        <div class="flex justify-end gap-3 border-t border-slate-100 pt-5 dark:border-slate-700">
          <button
            type="button"
            :disabled="!hasChanges || saving"
            class="flex items-center gap-1.5 rounded-lg px-4 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-40 dark:text-slate-300 dark:hover:bg-slate-700"
            @click="resetChanges"
          >
            <RotateCcw :size="15" />
            撤销修改
          </button>
          <button
            type="button"
            :disabled="!hasChanges || saving"
            class="flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
            @click="requestSave"
          >
            <LoaderCircle v-if="saving" :size="15" class="animate-spin" />
            <Save v-else :size="15" />
            {{ saving ? '保存中...' : '保存设置' }}
          </button>
        </div>
      </div>
    </div>

    <Ikev2ServiceSettings />

    <ConfirmDialog
      :open="confirmClearOpen"
      message="确定要清空网络编码白名单吗？清空后将允许任意网络编码的新连接和重连。"
      confirm-text="确认清空"
      :loading="saving"
      @close="confirmClearOpen = false"
      @confirm="saveSettings"
    />
  </div>
</template>
