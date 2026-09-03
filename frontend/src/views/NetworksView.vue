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
import type {
  CreateNetworkPayload,
  NetworkIkev2Info,
  NetworkInfo,
  NetworkType,
  UpdateNetworkIkev2Payload,
} from '@/types'

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

// ---------- 当前网络 IKEv2 ----------
const showIkev2Modal = ref(false)
const ikev2Loading = ref(false)
const ikev2Saving = ref(false)
const ikev2Target = ref<NetworkInfo | null>(null)
const ikev2Info = ref<NetworkIkev2Info | null>(null)
const ikev2Form = reactive({
  enabled: false,
  psk: '',
  clear_psk: false,
  eap_users: [] as Array<{ username: string; password: string; existing: boolean }>,
})

async function openIkev2Modal(net: NetworkInfo) {
  ikev2Target.value = net
  ikev2Info.value = null
  ikev2Form.enabled = false
  ikev2Form.psk = ''
  ikev2Form.clear_psk = false
  ikev2Form.eap_users = []
  showIkev2Modal.value = true
  ikev2Loading.value = true
  try {
    const info = await networkApi.getIkev2(net.network_code)
    ikev2Info.value = info
    ikev2Form.enabled = info.enabled
    ikev2Form.eap_users = info.eap_users.map((username) => ({
      username,
      password: '',
      existing: true,
    }))
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '加载 IKEv2 配置失败')
  } finally {
    ikev2Loading.value = false
  }
}

function addEapUser() {
  ikev2Form.eap_users.push({ username: '', password: '', existing: false })
}

function removeEapUser(index: number) {
  ikev2Form.eap_users.splice(index, 1)
}

async function saveIkev2() {
  if (!ikev2Target.value || !ikev2Info.value || ikev2Saving.value) return
  const usernames = ikev2Form.eap_users.map((user) => user.username.trim())
  if (usernames.some((username) => !username) || new Set(usernames).size !== usernames.length) {
    toast.error('EAP 用户名不能为空或重复')
    return
  }
  const missingPassword = ikev2Form.eap_users.some(
    (user) => !user.existing && !user.password,
  )
  if (missingPassword) {
    toast.error('新增 EAP 用户必须填写密码')
    return
  }
  const payload: UpdateNetworkIkev2Payload = {
    enabled: ikev2Form.enabled,
    clear_psk: ikev2Form.clear_psk,
    eap_users: ikev2Form.eap_users.map((user) => ({
      username: user.username.trim(),
      ...(user.password ? { password: user.password } : {}),
    })),
  }
  if (ikev2Form.psk) payload.psk = ikev2Form.psk

  ikev2Saving.value = true
  try {
    const info = await networkApi.updateIkev2(ikev2Target.value.network_code, payload)
    ikev2Info.value = info
    ikev2Form.psk = ''
    ikev2Form.clear_psk = false
    ikev2Form.eap_users = info.eap_users.map((username) => ({
      username,
      password: '',
      existing: true,
    }))
    if (info.restart_required) {
      toast.info('IKEv2 配置已保存，重启 vnts 后生效')
    } else {
      toast.success('IKEv2 配置已保存并热加载')
    }
    showIkev2Modal.value = false
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '保存 IKEv2 配置失败')
  } finally {
    ikev2Saving.value = false
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
        @ikev2="openIkev2Modal(net)"
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

    <BaseModal
      :open="showIkev2Modal"
      :title="`IKEv2 · ${ikev2Target?.network_code || ''}`"
      wide
      @close="showIkev2Modal = false"
    >
      <div v-if="ikev2Loading" class="flex items-center justify-center gap-2 py-10 text-sm text-slate-400">
        <LoaderCircle :size="16" class="animate-spin" />
        正在读取 IKEv2 配置...
      </div>
      <div v-else-if="ikev2Info" class="space-y-5">
        <div
          v-if="!ikev2Info.service_configured"
          class="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm leading-6 text-amber-700 dark:border-amber-800 dark:bg-amber-500/10 dark:text-amber-300"
        >
          IKEv2 服务尚未配置。请先在 config.toml 添加全局 [ikev2] 监听、Remote ID 和证书配置并重启 vnts。
        </div>

        <div v-else class="grid gap-3 rounded-lg border border-slate-200 bg-slate-50 p-4 text-xs dark:border-slate-700 dark:bg-slate-900/60 sm:grid-cols-2">
          <div><span class="text-slate-400">IKE：</span><span class="font-mono text-slate-700 dark:text-slate-300">{{ ikev2Info.ike_bind }}</span></div>
          <div><span class="text-slate-400">NAT-T：</span><span class="font-mono text-slate-700 dark:text-slate-300">{{ ikev2Info.natt_bind }}</span></div>
          <div><span class="text-slate-400">Remote ID：</span><span class="font-mono text-slate-700 dark:text-slate-300">{{ ikev2Info.remote_id }}</span></div>
          <div><span class="text-slate-400">运行状态：</span><span :class="ikev2Info.runtime_active ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'">{{ ikev2Info.runtime_active ? '已启动' : '等待重启' }}</span></div>
          <div><span class="text-slate-400">服务端证书：</span><span :class="ikev2Info.certificate_configured ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500'">{{ ikev2Info.certificate_configured ? '已配置' : '未配置（不能启用 EAP）' }}</span></div>
          <div><span class="text-slate-400">DNS：</span><span class="font-mono text-slate-700 dark:text-slate-300">{{ ikev2Info.dns.join(', ') || '-' }}</span></div>
        </div>

        <label class="flex items-center justify-between rounded-lg border border-slate-200 px-4 py-3 dark:border-slate-700">
          <div>
            <div class="text-sm font-medium text-slate-800 dark:text-slate-200">允许 IKEv2 接入当前网络</div>
            <div class="mt-0.5 text-xs text-slate-400">关闭后会删除该网络的认证配置并断开现有 IKEv2 会话</div>
          </div>
          <input v-model="ikev2Form.enabled" type="checkbox" class="h-4 w-4 accent-blue-600" :disabled="!ikev2Info.service_configured" />
        </label>

        <template v-if="ikev2Form.enabled">
          <div>
            <div class="mb-1.5 flex items-center justify-between">
              <label class="text-sm font-medium text-slate-700 dark:text-slate-300">预共享密钥（PSK）</label>
              <span v-if="ikev2Info.psk_configured" class="text-xs text-emerald-600 dark:text-emerald-400">已配置</span>
            </div>
            <input v-model="ikev2Form.psk" type="password" autocomplete="new-password" :class="inputClass" :placeholder="ikev2Info.psk_configured ? '留空保留原密钥' : '输入新的 PSK'" />
            <label v-if="ikev2Info.psk_configured" class="mt-2 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <input v-model="ikev2Form.clear_psk" type="checkbox" class="accent-red-500" />
              删除现有 PSK
            </label>
          </div>

          <div>
            <div class="mb-2 flex items-center justify-between">
              <div>
                <div class="text-sm font-medium text-slate-700 dark:text-slate-300">EAP 用户</div>
                <div class="mt-0.5 text-xs text-slate-400">已有用户密码留空表示不修改</div>
              </div>
              <button type="button" class="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-blue-600 hover:bg-blue-50 dark:border-slate-600 dark:text-blue-400 dark:hover:bg-blue-500/10" @click="addEapUser">添加用户</button>
            </div>
            <div v-if="ikev2Form.eap_users.length" class="space-y-2">
              <div v-for="(user, index) in ikev2Form.eap_users" :key="`${index}-${user.username}`" class="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_1fr_auto]">
                <input v-model="user.username" type="text" :class="inputClass" placeholder="用户名" />
                <input v-model="user.password" type="password" autocomplete="new-password" :class="inputClass" :placeholder="user.existing ? '留空保留密码' : '密码'" />
                <button type="button" class="rounded-lg px-3 text-sm text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10" @click="removeEapUser(index)">删除</button>
              </div>
            </div>
            <div v-else class="rounded-lg border border-dashed border-slate-200 py-5 text-center text-xs text-slate-400 dark:border-slate-700">未配置 EAP 用户</div>
          </div>
        </template>

        <div class="flex justify-end gap-3 border-t border-slate-100 pt-4 dark:border-slate-700">
          <button type="button" class="rounded-lg px-4 py-2 text-sm text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-700" @click="showIkev2Modal = false">取消</button>
          <button type="button" class="flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white disabled:opacity-50" :disabled="ikev2Saving || !ikev2Info.service_configured" @click="saveIkev2">
            <LoaderCircle v-if="ikev2Saving" :size="14" class="animate-spin" />
            {{ ikev2Saving ? '保存中...' : '保存 IKEv2' }}
          </button>
        </div>
      </div>
      <div v-else class="rounded-lg border border-red-200 bg-red-50 px-4 py-5 text-sm text-red-600 dark:border-red-900 dark:bg-red-500/10 dark:text-red-300">
        无法读取当前网络的 IKEv2 配置，请关闭窗口后重试。
      </div>
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
