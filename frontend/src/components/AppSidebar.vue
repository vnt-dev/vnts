<script setup lang="ts">
import { ChevronDown, Link2, Network, Route, Radio, Server, Settings, ShieldCheck, Waves } from '@lucide/vue'
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import AppLogo from './AppLogo.vue'
import { useSettingsNavigation } from '@/composables/useSettingsNavigation'

const { sectionStates } = useSettingsNavigation()
const route = useRoute()
const settingsActive = computed(() => route.name === 'settings')
const activeSettingsSection = computed(() =>
  route.query.section === 'client-access' || route.query.section === 'ikev2' || route.query.section === 'wireguard'
    ? route.query.section
    : 'access-control',
)
</script>

<template>
  <aside class="fixed inset-y-0 left-0 z-30 hidden w-56 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 lg:flex">
    <div class="flex h-16 items-center border-b border-slate-100 dark:border-slate-800 px-5">
      <AppLogo />
    </div>

    <nav class="flex-1 space-y-1 px-3 py-4">
      <RouterLink
        to="/networks"
        class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
        active-class="!bg-blue-50 !font-semibold !text-blue-700 dark:!bg-blue-500/15 dark:!text-blue-400"
      >
        <Network :size="18" />
        网络管理
      </RouterLink>
      <RouterLink
        to="/servers"
        class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
        active-class="!bg-blue-50 !font-semibold !text-blue-700 dark:!bg-blue-500/15 dark:!text-blue-400"
      >
        <Server :size="18" />
        服务器列表
      </RouterLink>
      <RouterLink
        to="/port-mappings"
        class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
        active-class="!bg-blue-50 !font-semibold !text-blue-700 dark:!bg-blue-500/15 dark:!text-blue-400"
      >
        <Route :size="18" />
        端口映射
      </RouterLink>
      <div>
        <RouterLink
          :to="{ name: 'settings', query: { section: 'access-control' } }"
          class="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
          active-class="!bg-blue-50 !font-semibold !text-blue-700 dark:!bg-blue-500/15 dark:!text-blue-400"
        >
          <Settings :size="18" />
          <span class="flex-1">系统设置</span>
          <ChevronDown :size="15" class="transition-transform" :class="settingsActive ? 'rotate-0' : '-rotate-90'" />
        </RouterLink>

        <Transition name="submenu">
          <div v-if="settingsActive" class="relative ml-5 mt-1 space-y-1 border-l border-slate-200 pl-3 dark:border-slate-700">
            <RouterLink
              :to="{ name: 'settings', query: { section: 'access-control' } }"
              class="settings-submenu-item"
              :class="activeSettingsSection === 'access-control' ? 'settings-submenu-active' : ''"
            >
              <ShieldCheck :size="15" class="shrink-0" />
              <span class="min-w-0 flex-1 truncate">访问控制</span>
              <span v-if="sectionStates['access-control'].dirty" class="h-2 w-2 shrink-0 rounded-full bg-amber-500" title="有未保存修改"></span>
            </RouterLink>
            <RouterLink
              :to="{ name: 'settings', query: { section: 'client-access' } }"
              class="settings-submenu-item"
              :class="activeSettingsSection === 'client-access' ? 'settings-submenu-active' : ''"
            >
              <Link2 :size="15" class="shrink-0" />
              <span class="min-w-0 flex-1 truncate">客户端接入</span>
              <span v-if="sectionStates['client-access'].dirty" class="h-2 w-2 shrink-0 rounded-full bg-amber-500" title="有未保存修改"></span>
            </RouterLink>
            <RouterLink
              :to="{ name: 'settings', query: { section: 'ikev2' } }"
              class="settings-submenu-item"
              :class="activeSettingsSection === 'ikev2' ? 'settings-submenu-active' : ''"
            >
              <Radio :size="15" class="shrink-0" />
              <span class="min-w-0 flex-1 truncate">IKEv2 服务</span>
              <span v-if="sectionStates.ikev2.dirty" class="h-2 w-2 shrink-0 rounded-full bg-amber-500" title="有未保存修改"></span>
            </RouterLink>
            <RouterLink
              :to="{ name: 'settings', query: { section: 'wireguard' } }"
              class="settings-submenu-item"
              :class="activeSettingsSection === 'wireguard' ? 'settings-submenu-active' : ''"
            >
              <Waves :size="15" class="shrink-0" />
              <span class="min-w-0 flex-1 truncate">WireGuard 服务</span>
              <span v-if="sectionStates.wireguard.dirty" class="h-2 w-2 shrink-0 rounded-full bg-amber-500" title="有未保存修改"></span>
            </RouterLink>
          </div>
        </Transition>
      </div>
    </nav>
  </aside>
</template>

<style scoped>
@reference "../style.css";
.settings-submenu-item { @apply flex min-h-9 items-center gap-2 rounded-lg px-2 py-2 text-xs font-medium text-slate-500 transition hover:bg-slate-50 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200; }
.settings-submenu-active { @apply bg-slate-100 font-semibold text-blue-700 dark:bg-slate-800 dark:text-blue-400; }
.submenu-enter-active, .submenu-leave-active { transition: opacity 0.15s ease, transform 0.15s ease; }
.submenu-enter-from, .submenu-leave-to { opacity: 0; transform: translateY(-4px); }
</style>
