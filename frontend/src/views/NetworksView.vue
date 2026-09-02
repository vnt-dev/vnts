<script setup lang="ts">
import { LoaderCircle, Plus, Search } from '@lucide/vue'
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import { networkApi } from '@/api/modules'
import BaseModal from '@/components/BaseModal.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import NetworkCard from '@/components/NetworkCard.vue'
import { useToast } from '@/composables/useToast'
import type { CreateNetworkPayload, NetworkInfo, NetworkType } from '@/types'

const router = useRouter()
const toast = useToast()

const networks = ref<NetworkInfo[]>([])
const loading = ref(false)
const search = ref('')

const filteredNetworks = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return networks.value
  return networks.value.filter((n) => n.network_code.toLowerCase().includes(q))
})

async function fetchNetworks() {
  loading.value = true
  try {
    networks.value = await networkApi.list()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '加载网络列表失败')
  } finally {
    loading.value = false
  }
}

onMounted(fetchNetworks)

function selectNetwork(net: NetworkInfo) {
  router.push({ name: 'devices', params: { code: net.network_code } })
}

// ---------- 新增 / 编辑网络 ----------
const showFormModal = ref(false)
const isEditMode = ref(false)
const formSubmitting = ref(false)
const form = reactive({
  network_code: '',
  gateway: '',
  netmask: 24,
  lease_duration: null as number | null,
  network_type: 'Public' as NetworkType,
})

const inputClass =
  'w-full rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm text-slate-800 placeholder:text-slate-400 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 disabled:bg-slate-50 disabled:text-slate-500 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200 dark:placeholder:text-slate-500 dark:focus:border-blue-500 dark:focus:ring-blue-500/20 dark:disabled:bg-slate-800/50 dark:disabled:text-slate-600'

const searchInputClass =
  'w-full rounded-lg border border-slate-200 bg-white py-2 pl-9 pr-3.5 text-sm text-slate-800 placeholder:text-slate-400 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200 dark:placeholder:text-slate-500 dark:focus:border-blue-500 dark:focus:ring-blue-500/20'

function openCreateModal() {
  isEditMode.value = false
  form.network_code = ''
  form.gateway = ''
  form.netmask = 24
  form.lease_duration = null
  form.network_type = 'Public'
  showFormModal.value = true
}

function openEditModal(net: NetworkInfo) {
  isEditMode.value = true
  form.network_code = net.network_code
  form.gateway = net.gateway
  form.netmask = net.netmask
  form.lease_duration = net.lease_duration
  form.network_type = net.network_type ?? 'Public'
  showFormModal.value = true
}

async function submitForm() {
  if (formSubmitting.value) return
  if (isEditMode.value && !form.lease_duration) {
    toast.error('请输入有效的 IP 租期')
    return
  }
  formSubmitting.value = true
  try {
    if (isEditMode.value) {
      await networkApi.update(form.network_code, {
        gateway: form.gateway,
        netmask: form.netmask,
        lease_duration: form.lease_duration as number,
        network_type: form.network_type,
      })
    } else {
      const payload: CreateNetworkPayload = {
        network_code: form.network_code,
        gateway: form.gateway,
        netmask: form.netmask,
        network_type: form.network_type,
      }
      if (form.lease_duration) payload.lease_duration = form.lease_duration
      await networkApi.create(payload)
    }
    showFormModal.value = false
    toast.success(isEditMode.value ? '网络更新成功' : '网络创建成功')
    void fetchNetworks()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '提交失败')
  } finally {
    formSubmitting.value = false
  }
}

// ---------- 删除网络 ----------
const confirmOpen = ref(false)
const confirmMessage = ref('')
const deleteTarget = ref<NetworkInfo | null>(null)
const deleting = ref(false)

function confirmDelete(net: NetworkInfo) {
  deleteTarget.value = net
  confirmMessage.value = `确定要删除网络 "${net.network_code}" 吗？此操作不可撤销。`
  confirmOpen.value = true
}

async function executeDelete() {
  if (!deleteTarget.value || deleting.value) return
  deleting.value = true
  try {
    await networkApi.remove(deleteTarget.value.network_code)
    confirmOpen.value = false
    toast.success('网络已删除')
    void fetchNetworks()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '删除网络失败')
  } finally {
    deleting.value = false
  }
}
</script>

<template>
  <div>
    <!-- 页头 -->
    <div class="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h2 class="text-xl font-bold text-slate-900 dark:text-slate-100">网络列表</h2>
        <p class="mt-0.5 text-sm text-slate-400 dark:text-slate-500">共 {{ networks.length }} 个虚拟网络</p>
      </div>
      <div class="flex items-center gap-3">
        <div class="relative w-full sm:w-64">
          <Search :size="15" class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          <input
            v-model="search"
            type="text"
            :class="searchInputClass"
            placeholder="搜索网络代码..."
          />
        </div>
        <button
          class="flex shrink-0 items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-blue-700"
          @click="openCreateModal"
        >
          <Plus :size="16" />
          新增网络
        </button>
      </div>
    </div>

    <!-- 列表 -->
    <div v-if="loading" class="flex justify-center py-16">
      <LoaderCircle :size="28" class="animate-spin text-blue-500" />
    </div>

    <div v-else-if="filteredNetworks.length === 0" class="rounded-xl border border-dashed border-slate-300 bg-white py-16 text-center text-sm text-slate-400 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-500">
      未找到匹配的网络
    </div>

    <div v-else class="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3">
      <NetworkCard
        v-for="net in filteredNetworks"
        :key="net.network_code"
        :network="net"
        @select="selectNetwork(net)"
        @edit="openEditModal(net)"
        @remove="confirmDelete(net)"
      />
    </div>

    <!-- 新增/编辑网络弹窗 -->
    <BaseModal :open="showFormModal" :title="isEditMode ? '编辑网络' : '新增网络'" @close="showFormModal = false">
      <form class="space-y-4" @submit.prevent="submitForm">
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">网络编号</label>
          <input
            v-model.trim="form.network_code"
            type="text"
            :class="inputClass"
            :disabled="isEditMode"
            placeholder="如: office, home"
            required
          />
        </div>
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">网络类型</label>
          <select v-model="form.network_type" :class="inputClass">
            <option value="Public">公开网络</option>
            <option value="Private">私有网络</option>
          </select>
          <p
            class="mt-1.5 rounded-md px-2.5 py-2 text-xs leading-5"
            :class="form.network_type === 'Private' ? 'bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400' : 'bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400'"
          >
            <template v-if="form.network_type === 'Private'">
              私有网络：仅允许设备列表中已有的设备 ID 连接，新设备需先手动添加。
            </template>
            <template v-else>
              公开网络：允许新设备直接注册，服务端会自动分配并记录设备。
            </template>
          </p>
        </div>
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">网关地址</label>
          <input
            v-model.trim="form.gateway"
            type="text"
            :class="inputClass"
            placeholder="如: 10.26.0.1"
            required
          />
        </div>
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">掩码长度</label>
          <input
            v-model.number="form.netmask"
            type="number"
            :class="inputClass"
            min="8"
            max="30"
            placeholder="如: 24"
            required
          />
        </div>
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">IP 租期（秒）</label>
          <input
            v-model.number="form.lease_duration"
            type="number"
            :class="inputClass"
            min="60"
            :required="isEditMode"
            placeholder="如: 86400 (24小时)"
          />
          <p v-if="!isEditMode" class="mt-1 text-xs text-slate-400 dark:text-slate-500">新增时不填则使用默认值</p>
        </div>
        <div class="flex justify-end gap-3 pt-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-700"
            @click="showFormModal = false"
          >
            取消
          </button>
          <button
            type="submit"
            :disabled="formSubmitting"
            class="flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60"
          >
            <LoaderCircle v-if="formSubmitting" :size="14" class="animate-spin" />
            {{ formSubmitting ? '提交中...' : '确定' }}
          </button>
        </div>
      </form>
    </BaseModal>

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
