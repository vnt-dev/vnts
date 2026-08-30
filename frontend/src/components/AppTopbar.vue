<script setup lang="ts">
import { LogOut, Network, Server } from '@lucide/vue'
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AppLogo from './AppLogo.vue'
import { useAuthStore } from '@/composables/useAuth'

const route = useRoute()
const router = useRouter()
const { username, logout } = useAuthStore()

const title = computed(() => (route.meta.title as string | undefined) ?? 'vnt 控制中心')

function handleLogout() {
  logout()
  router.push({ name: 'login' })
}
</script>

<template>
  <header class="sticky top-0 z-20 border-b border-slate-200 bg-white/90 backdrop-blur">
    <div class="flex h-16 items-center justify-between gap-3 px-4 sm:px-6 lg:px-8">
      <div class="flex min-w-0 items-center gap-3">
        <div class="lg:hidden">
          <AppLogo />
        </div>
        <h1 class="truncate text-lg font-bold text-slate-900">{{ title }}</h1>
      </div>

      <div class="flex shrink-0 items-center gap-2">
        <!-- 移动端导航 -->
        <nav class="flex items-center gap-1 lg:hidden">
          <RouterLink
            to="/networks"
            class="rounded-lg p-2 text-slate-500 transition hover:bg-slate-100 hover:text-blue-600"
            active-class="!bg-blue-50 !text-blue-700"
            title="网络管理"
          >
            <Network :size="18" />
          </RouterLink>
          <RouterLink
            to="/servers"
            class="rounded-lg p-2 text-slate-500 transition hover:bg-slate-100 hover:text-blue-600"
            active-class="!bg-blue-50 !text-blue-700"
            title="服务器列表"
          >
            <Server :size="18" />
          </RouterLink>
        </nav>

        <span class="hidden text-sm text-slate-500 sm:inline">{{ username || 'Admin' }}</span>
        <button
          class="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-sm font-medium text-slate-500 transition hover:bg-red-50 hover:text-red-600"
          @click="handleLogout"
        >
          <LogOut :size="16" />
          <span class="hidden sm:inline">退出登录</span>
        </button>
      </div>
    </div>
  </header>
</template>