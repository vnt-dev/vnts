<script setup lang="ts">
import { LoaderCircle, LogIn, LogOut, Plus } from '@lucide/vue'
import { onMounted, ref } from 'vue'
import { ApiError } from '@/api/client'
import { peerServerApi } from '@/api/modules'
import BaseModal from '@/components/BaseModal.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import PeerServerCard from '@/components/PeerServerCard.vue'
import { useToast } from '@/composables/useToast'
import type { PeerServerInfo, PeerServersResponse } from '@/types'

const toast = useToast()

const peerServers = ref<PeerServersResponse>({ outbound: [], inbound: [] })
const loading = ref(false)

async function fetchPeerServers() {
  loading.value = true
  try {
    peerServers.value = await peerServerApi.list()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '加载服务器列表失败')
  } finally {
    loading.value = false
  }
}

onMounted(fetchPeerServers)

// ---------- 添加服务器 ----------
const showAddModal = ref(false)
const adding = ref(false)
const serverAddr = ref('')

const inputClass =
  'w-full rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm text-slate-800 placeholder:text-slate-400 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200 dark:placeholder:text-slate-500 dark:focus:border-blue-500 dark:focus:ring-blue-500/20'

async function submitAdd() {
  if (adding.value) return
  const addr = serverAddr.value.trim()
  if (!addr) return
  adding.value = true
  try {
    await peerServerApi.add(addr)
    showAddModal.value = false
    toast.success('服务器添加成功')
    void fetchPeerServers()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '添加失败')
  } finally {
    adding.value = false
  }
}

// ---------- 删除服务器 ----------
const confirmOpen = ref(false)
const confirmMessage = ref('')
const deleteTarget = ref<PeerServerInfo | null>(null)
const deleting = ref(false)

function confirmRemove(server: PeerServerInfo) {
  deleteTarget.value = server
  confirmMessage.value = `确定要删除服务器 "${server.addr}" 吗？此操作将断开连接并从列表中移除。`
  confirmOpen.value = true
}

async function executeDelete() {
  if (!deleteTarget.value || deleting.value) return
  deleting.value = true
  try {
    await peerServerApi.remove(deleteTarget.value.addr)
    confirmOpen.value = false
    toast.success('服务器已删除')
    void fetchPeerServers()
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '删除服务器失败')
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
        <h2 class="text-xl font-bold text-slate-900 dark:text-slate-100">服务器列表</h2>
        <p class="mt-0.5 text-sm text-slate-400 dark:text-slate-500">vnt 服务端之间的互联节点</p>
      </div>
      <button
        class="flex shrink-0 items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-blue-700"
        @click="showAddModal = true"
      >
        <Plus :size="16" />
        添加服务器
      </button>
    </div>

    <div v-if="loading" class="flex justify-center bg-white py-20 shadow-sm dark:bg-slate-800">
      <LoaderCircle :size="28" class="animate-spin text-blue-500" />
    </div>

    <template v-else>
      <!-- 主动连接的服务器 -->
      <section class="mb-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
        <h3 class="mb-4 flex items-center gap-2 text-base font-bold text-slate-900 dark:text-slate-100">
          <span class="flex h-7 w-7 items-center justify-center rounded-lg bg-blue-50 text-blue-600 dark:bg-blue-500/10 dark:text-blue-400">
            <LogOut :size="15" />
          </span>
          主动连接的服务器
          <span class="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-500 dark:bg-slate-700/60 dark:text-slate-400">
            {{ peerServers.outbound.length }}
          </span>
        </h3>
        <div
          v-if="peerServers.outbound.length === 0"
          class="rounded-lg border border-dashed border-slate-200 py-10 text-center text-sm text-slate-400 dark:border-slate-600 dark:text-slate-500"
        >
          暂无主动连接的服务器
        </div>
        <div v-else class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          <PeerServerCard
            v-for="server in peerServers.outbound"
            :key="server.addr"
            :server="server"
            direction="outbound"
            @remove="confirmRemove(server)"
          />
        </div>
      </section>

      <!-- 被动接受的服务器 -->
      <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
        <h3 class="mb-4 flex items-center gap-2 text-base font-bold text-slate-900 dark:text-slate-100">
          <span class="flex h-7 w-7 items-center justify-center rounded-lg bg-purple-50 text-purple-600 dark:bg-purple-500/10 dark:text-purple-400">
            <LogIn :size="15" />
          </span>
          被动接受的服务器
          <span class="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-500 dark:bg-slate-700/60 dark:text-slate-400">
            {{ peerServers.inbound.length }}
          </span>
        </h3>
        <div
          v-if="peerServers.inbound.length === 0"
          class="rounded-lg border border-dashed border-slate-200 py-10 text-center text-sm text-slate-400 dark:border-slate-600 dark:text-slate-500"
        >
          暂无被动接受的服务器连接
        </div>
        <div v-else class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          <PeerServerCard
            v-for="server in peerServers.inbound"
            :key="server.addr"
            :server="server"
            direction="inbound"
            @remove="confirmRemove(server)"
          />
        </div>
      </section>
    </template>

    <!-- 添加服务器弹窗 -->
    <BaseModal :open="showAddModal" title="添加服务器" @close="showAddModal = false">
      <form class="space-y-4" @submit.prevent="submitAdd">
        <div>
          <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">服务器地址</label>
          <input
            v-model.trim="serverAddr"
            type="text"
            :class="inputClass"
            placeholder="如: 192.168.1.100:8080"
            required
          />
          <p class="mt-1 text-xs text-slate-400 dark:text-slate-500">格式: IP:端口 或 域名:端口</p>
        </div>
        <div class="flex justify-end gap-3 pt-2">
          <button
            type="button"
            class="rounded-lg px-4 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-700"
            @click="showAddModal = false"
          >
            取消
          </button>
          <button
            type="submit"
            :disabled="adding"
            class="flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60"
          >
            <LoaderCircle v-if="adding" :size="14" class="animate-spin" />
            {{ adding ? '添加中...' : '确定' }}
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