<script setup lang="ts">
import { LogOut, Network, Server } from '@lucide/vue'
import { useRouter } from 'vue-router'
import AppLogo from './AppLogo.vue'
import { useAuthStore } from '@/composables/useAuth'

const { username, logout } = useAuthStore()
const router = useRouter()

function handleLogout() {
  logout()
  router.push({ name: 'login' })
}
</script>

<template>
  <aside class="fixed inset-y-0 left-0 z-30 hidden w-56 flex-col border-r border-slate-200 bg-white lg:flex">
    <div class="flex h-16 items-center border-b border-slate-100 px-5">
      <AppLogo />
    </div>

    <nav class="flex-1 space-y-1 px-3 py-4">
      <RouterLink
        to="/networks"
        class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
        active-class="!bg-blue-50 !font-semibold !text-blue-700"
      >
        <Network :size="18" />
        网络管理
      </RouterLink>
      <RouterLink
        to="/servers"
        class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
        active-class="!bg-blue-50 !font-semibold !text-blue-700"
      >
        <Server :size="18" />
        服务器列表
      </RouterLink>
    </nav>

    <div class="border-t border-slate-100 p-3">
      <div class="flex items-center gap-3 rounded-lg bg-slate-50 px-3 py-2.5">
        <div
          class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-blue-100 text-xs font-bold text-blue-700"
        >
          {{ (username || 'A').charAt(0).toUpperCase() }}
        </div>
        <div class="min-w-0 flex-1">
          <div class="truncate text-sm font-medium text-slate-800">{{ username || 'Admin' }}</div>
          <div class="text-[11px] text-slate-400">管理员</div>
        </div>
        <button
          class="shrink-0 rounded-lg p-1 text-slate-400 transition hover:bg-red-50 hover:text-red-500"
          title="退出登录"
          @click="handleLogout"
        >
          <LogOut :size="16" />
        </button>
      </div>
    </div>
  </aside>
</template>