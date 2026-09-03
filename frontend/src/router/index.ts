import { createRouter, createWebHashHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/composables/useAuth'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    meta: { public: true },
  },
  {
    path: '/networks',
    name: 'networks',
    component: () => import('@/views/NetworksView.vue'),
    meta: { title: '网络管理' },
  },
  {
    path: '/devices/:code',
    name: 'devices',
    component: () => import('@/views/DevicesView.vue'),
    meta: { title: '网络详情' },
  },
  {
    path: '/servers',
    name: 'servers',
    component: () => import('@/views/ServersView.vue'),
    meta: { title: '服务器列表' },
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('@/views/SettingsView.vue'),
    meta: { title: '系统设置' },
  },
  { path: '/', redirect: '/networks' },
  { path: '/:pathMatch(.*)*', redirect: '/networks' },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

router.beforeEach((to) => {
  const { isLoggedIn } = useAuthStore()
  if (!to.meta.public && !isLoggedIn.value) {
    return { name: 'login' }
  }
  if (to.name === 'login' && isLoggedIn.value) {
    return { name: 'networks' }
  }
  return true
})

export default router
