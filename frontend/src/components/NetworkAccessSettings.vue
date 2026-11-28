<script setup lang="ts">
import {
  AlertCircle,
  CheckCircle2,
  Info,
  LoaderCircle,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldCheck,
  X,
} from '@lucide/vue'
import { computed, onMounted, ref, watch } from 'vue'
import { ApiError } from '@/api/client'
import { networkApi, settingsApi } from '@/api/modules'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import { useToast } from '@/composables/useToast'
import type { SettingsSectionState } from '@/composables/useSettingsNavigation'
import type { NetworkWhitelistSettings } from '@/types'

const emit = defineEmits<{
  state: [value: SettingsSectionState]
}>()

const toast = useToast()
const loading = ref(false)
const saving = ref(false)
const loadError = ref('')
const confirmClearOpen = ref(false)
const matchModes = [
  { value: 'network_codes', label: '精确匹配' },
  { value: 'network_patterns', label: '通配符匹配' },
] as const
type MatchMode = keyof NetworkWhitelistSettings

const savedRules = ref<NetworkWhitelistSettings>({ network_codes: [], network_patterns: [] })
const rules = ref<NetworkWhitelistSettings>({ network_codes: [], network_patterns: [] })
const existingCodes = ref<string[]>([])
const input = ref('')
const matchMode = ref<MatchMode>('network_codes')

const ruleCount = computed(() => rules.value.network_codes.length + rules.value.network_patterns.length)
const hasChanges = computed(() => matchModes.some(({ value }) => {
  const current = rules.value[value]
  const saved = new Set(savedRules.value[value])
  return current.length !== saved.size || current.some((rule) => !saved.has(rule))
}))

const availableSuggestions = computed(() => {
  if (matchMode.value !== 'network_codes') return []
  const selected = new Set(rules.value.network_codes)
  const query = input.value.trim().toLowerCase()
  return existingCodes.value.filter(
    (code) => !selected.has(code) && (!query || code.toLowerCase().includes(query)),
  )
})

const status = computed(() => {
  if (loadError.value) return { text: '加载失败', tone: 'danger' as const }
  if (loading.value) return { text: '正在读取', tone: 'neutral' as const }
  if (ruleCount.value === 0) return { text: '允许所有网络', tone: 'warning' as const }
  return { text: `${ruleCount.value} 条允许规则`, tone: 'success' as const }
})

watch(
  [status, hasChanges],
  () => emit('state', { status: status.value.text, tone: status.value.tone, dirty: hasChanges.value }),
  { immediate: true },
)

async function loadSettings() {
  loading.value = true
  loadError.value = ''
  try {
    const [settings, networkCodes] = await Promise.all([
      settingsApi.getNetworkWhitelist(),
      networkApi.codes(),
    ])
    applySettings(settings)
    existingCodes.value = [...networkCodes].sort()
  } catch (error) {
    loadError.value = error instanceof ApiError ? error.message : '无法读取网络访问策略'
  } finally {
    loading.value = false
  }
}

function addCode(rawCode: string, mode: MatchMode) {
  const code = rawCode.trim()
  if (!code) return true
  if (new TextEncoder().encode(code).length > 32) {
    toast.error(`规则“${code}”超过 32 字节`)
    return false
  }
  if (mode === 'network_patterns' && (!code.includes('*') || /^\*+$/.test(code))) {
    toast.error('通配符规则必须包含 * 和至少一个非星号字符')
    return false
  }
  if (!rules.value[mode].includes(code)) rules.value[mode].push(code)
  return true
}

function addTokens(raw: string) {
  const invalid = raw.split(/[,，\n\r]+/).filter((token) => !addCode(token, matchMode.value))
  input.value = invalid.join(', ')
  return invalid.length === 0
}

function commitInput() {
  return addTokens(input.value)
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

function removeCode(code: string, mode: MatchMode) {
  rules.value[mode] = rules.value[mode].filter((item) => item !== code)
}

function applySettings(settings: NetworkWhitelistSettings) {
  savedRules.value = settings
  resetChanges()
}

function resetChanges() {
  rules.value = {
    network_codes: [...savedRules.value.network_codes],
    network_patterns: [...savedRules.value.network_patterns],
  }
  input.value = ''
}

function requestSave() {
  if (saving.value || !commitInput() || !hasChanges.value) return
  if (ruleCount.value === 0) {
    confirmClearOpen.value = true
    return
  }
  void saveSettings()
}

async function saveSettings() {
  if (saving.value) return
  saving.value = true
  try {
    const settings = await settingsApi.updateNetworkWhitelist(rules.value)
    applySettings(settings)
    confirmClearOpen.value = false
    toast.success('网络访问策略已保存')
  } catch (error) {
    toast.error(error instanceof ApiError ? error.message : '保存网络访问策略失败')
  } finally {
    saving.value = false
  }
}

onMounted(loadSettings)
</script>

<template>
  <section aria-labelledby="access-control-title" class="space-y-4">
    <header class="rounded-xl border border-slate-200 bg-white px-5 py-4 shadow-sm dark:border-slate-700 dark:bg-slate-800 sm:px-6">
      <div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div class="flex items-start gap-3">
          <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-blue-50 text-blue-600 dark:bg-blue-500/10 dark:text-blue-400">
            <ShieldCheck :size="21" />
          </div>
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <h2 id="access-control-title" class="font-semibold text-slate-950 dark:text-white">网络访问控制</h2>
              <span class="status-pill" :class="`status-${status.tone}`">{{ status.text }}</span>
            </div>
            <p class="mt-1 text-sm leading-5 text-slate-500 dark:text-slate-400">只允许指定网络连接当前服务。</p>
            <details class="help-details mt-2">
              <summary>如何配置</summary>
              <p>添加允许连接的精确编码或通配符规则并保存。列表为空时允许所有网络，现有在线设备不会因修改立即断开。</p>
            </details>
          </div>
        </div>
      </div>
    </header>

    <div v-if="loading" class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-800" aria-label="正在加载访问控制设置">
      <div class="animate-pulse space-y-5">
        <div class="h-20 rounded-lg bg-slate-100 dark:bg-slate-700/70"></div>
        <div class="h-10 rounded-lg bg-slate-100 dark:bg-slate-700/70"></div>
        <div class="h-32 rounded-lg bg-slate-100 dark:bg-slate-700/70"></div>
      </div>
    </div>

    <div v-else-if="loadError" class="rounded-xl border border-red-200 bg-white p-8 text-center shadow-sm dark:border-red-500/30 dark:bg-slate-800">
      <AlertCircle :size="26" class="mx-auto text-red-500" />
      <h3 class="mt-3 font-semibold text-slate-900 dark:text-slate-100">访问策略加载失败</h3>
      <p class="mx-auto mt-1 max-w-md text-sm text-slate-500 dark:text-slate-400">{{ loadError }}</p>
      <button type="button" class="secondary-button mt-5" @click="loadSettings">
        <RefreshCw :size="15" />重新加载
      </button>
    </div>

    <div v-else class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800 sm:p-6">
      <div>
        <h3 class="text-sm font-semibold text-slate-900 dark:text-slate-100">允许的网络</h3>
        <div
          class="mt-3 flex gap-3 rounded-lg border px-4 py-3"
          :class="ruleCount === 0
            ? 'border-amber-200 bg-amber-50/70 dark:border-amber-500/25 dark:bg-amber-500/5'
            : 'border-emerald-200 bg-emerald-50/70 dark:border-emerald-500/25 dark:bg-emerald-500/5'"
        >
          <Info v-if="ruleCount === 0" :size="18" class="mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" />
          <CheckCircle2 v-else :size="18" class="mt-0.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
          <div>
            <p class="text-sm font-semibold text-slate-800 dark:text-slate-200">
              {{ ruleCount === 0 ? '允许所有网络连接' : '仅允许匹配任一规则的网络连接' }}
            </p>
            <p class="mt-1 text-sm leading-5 text-slate-500 dark:text-slate-400">{{ ruleCount === 0 ? '任何网络编码都可以连接。清空列表时需要再次确认。' : '新连接和重连会按此列表校验。' }}</p>
          </div>
        </div>
      </div>

      <div class="mt-5 border-t border-slate-100 pt-5 dark:border-slate-700">
        <label for="whitelist-match-mode" class="sr-only">匹配方式</label>
        <label for="whitelist-code" class="sr-only">网络编码或规则</label>
        <div class="grid grid-cols-[minmax(0,1fr)_auto] gap-2 sm:grid-cols-[auto_minmax(0,1fr)_auto]">
          <select id="whitelist-match-mode" v-model="matchMode" class="field col-span-2 w-full sm:col-span-1 sm:w-auto">
            <option v-for="mode in matchModes" :key="mode.value" :value="mode.value">{{ mode.label }}</option>
          </select>
          <input
            id="whitelist-code"
            v-model="input"
            type="text"
            :list="matchMode === 'network_codes' ? 'network-code-suggestions' : undefined"
            class="field w-full min-w-0"
            :placeholder="matchMode === 'network_codes' ? '输入网络编码' : '例如 office-*-vpn'"
            @keydown="handleKeydown"
            @paste="handlePaste"
          />
          <datalist id="network-code-suggestions">
            <option v-for="code in availableSuggestions" :key="code" :value="code" />
          </datalist>
          <button type="button" class="secondary-button" :disabled="!input.trim()" @click="commitInput">
            <Plus :size="16" />添加
          </button>
        </div>
        <details class="help-details mt-2">
          <summary>匹配与批量添加说明</summary>
          <p>精确匹配逐字比较。通配符规则中的 * 可放在任意位置，匹配零个或多个字符。两种方式都区分大小写。</p>
          <p>可粘贴以逗号或换行分隔的多条规则，统一使用当前匹配方式。每条规则最多 32 字节。</p>
        </details>
        <div v-if="availableSuggestions.length && !input" class="mt-3 flex flex-wrap items-center gap-2">
          <span class="text-sm text-slate-400 dark:text-slate-500">可快速添加：</span>
          <button
            v-for="code in availableSuggestions.slice(0, 6)"
            :key="code"
            type="button"
            class="rounded-md bg-slate-100 px-2.5 py-1 text-sm font-medium text-slate-600 transition hover:bg-blue-50 hover:text-blue-700 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-blue-500/10 dark:hover:text-blue-300"
            @click="addCode(code, 'network_codes')"
          >
            + {{ code }}
          </button>
        </div>
      </div>

      <div class="mt-5 border-t border-slate-100 pt-5 dark:border-slate-700">
        <div class="mb-3 flex items-center justify-between gap-3">
          <h3 class="text-sm font-semibold text-slate-900 dark:text-slate-100">当前列表</h3>
          <span class="text-sm text-slate-400 dark:text-slate-500">{{ ruleCount }} 项</span>
        </div>
        <div v-if="ruleCount === 0" class="rounded-lg border border-dashed border-slate-300 px-4 py-9 text-center dark:border-slate-600">
          <ShieldCheck :size="24" class="mx-auto text-slate-300 dark:text-slate-600" />
          <p class="mt-2 text-sm font-medium text-slate-600 dark:text-slate-300">白名单为空</p>
          <p class="mt-1 text-sm text-slate-400 dark:text-slate-500">当前服务不会按网络编码限制连接。</p>
        </div>
        <div v-else class="flex max-h-48 min-h-24 flex-wrap content-start gap-2 overflow-y-auto rounded-lg border border-slate-200 bg-slate-50/60 p-3 dark:border-slate-600 dark:bg-slate-900/40" tabindex="0" aria-label="允许的网络编码列表">
          <template v-for="mode in matchModes" :key="mode.value">
            <span v-for="code in rules[mode.value]" :key="code" class="code-chip">
              <span class="text-xs opacity-80">{{ mode.label }}</span>
              {{ code }}
              <button type="button" class="rounded p-0.5 transition hover:bg-blue-100 hover:text-blue-900 dark:hover:bg-blue-500/20 dark:hover:text-blue-100" :aria-label="`移除${mode.label} ${code}`" @click="removeCode(code, mode.value)">
                <X :size="13" />
              </button>
            </span>
          </template>
        </div>
      </div>
    </div>

    <Transition name="action-bar">
      <div v-if="hasChanges" class="sticky bottom-4 z-10 flex flex-col gap-3 rounded-xl border border-amber-200 bg-white/95 px-4 py-3 shadow-lg shadow-slate-900/10 backdrop-blur dark:border-amber-500/30 dark:bg-slate-800/95 sm:flex-row sm:items-center sm:justify-between">
        <p class="text-sm font-medium text-amber-700 dark:text-amber-300">访问策略有未保存的修改</p>
        <div class="flex justify-end gap-2">
          <button type="button" class="ghost-button" :disabled="saving" @click="resetChanges"><RotateCcw :size="15" />撤销</button>
          <button type="button" class="primary-button" :disabled="saving" @click="requestSave">
            <LoaderCircle v-if="saving" :size="15" class="animate-spin" />
            <Save v-else :size="15" />{{ saving ? '保存中...' : '保存策略' }}
          </button>
        </div>
      </div>
    </Transition>

    <ConfirmDialog
      :open="confirmClearOpen"
      message="确定要清空网络编码白名单吗？清空后将允许任意网络编码的新连接和重连。"
      confirm-text="确认清空"
      :loading="saving"
      @close="confirmClearOpen = false"
      @confirm="saveSettings"
    />
  </section>
</template>

<style scoped>
@reference "../style.css";
.field { @apply rounded-lg border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-800 placeholder:text-slate-400 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200 dark:focus:border-blue-500 dark:focus:ring-blue-500/20; }
.status-pill { @apply inline-flex w-fit shrink-0 items-center rounded-full px-2.5 py-1 text-xs font-semibold; }
.status-neutral { @apply bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300; }
.status-success { @apply bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300; }
.status-warning { @apply bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300; }
.status-danger { @apply bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-300; }
.secondary-button { @apply inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700; }
.ghost-button { @apply inline-flex items-center gap-1.5 rounded-lg px-3.5 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 disabled:opacity-50 dark:text-slate-300 dark:hover:bg-slate-700; }
.primary-button { @apply inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-50; }
.code-chip { @apply inline-flex h-8 items-center gap-1.5 rounded-lg border border-blue-200 bg-blue-50 px-2.5 text-sm font-medium text-blue-700 dark:border-blue-500/30 dark:bg-blue-500/10 dark:text-blue-300; }
.help-details summary { @apply inline-flex cursor-pointer list-none items-center gap-1 text-sm font-medium text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300; }
.help-details summary::after { content: ''; @apply h-1.5 w-1.5 rotate-45 border-b border-r border-current transition-transform; }
.help-details[open] summary::after { @apply rotate-[225deg]; }
.help-details p { @apply mt-2 max-w-2xl text-sm leading-6 text-slate-500 dark:text-slate-400; }
.action-bar-enter-active, .action-bar-leave-active { transition: opacity 0.16s ease, transform 0.16s ease; }
.action-bar-enter-from, .action-bar-leave-to { opacity: 0; transform: translateY(8px); }
</style>
