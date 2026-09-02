<script setup lang="ts">
import { Eye, EyeOff, LoaderCircle, Lock, Moon, Sun, User } from '@lucide/vue'
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import { authApi } from '@/api/modules'
import AppLogo from '@/components/AppLogo.vue'
import { useAuthStore } from '@/composables/useAuth'
import { useTheme } from '@/composables/useTheme'
import { useToast } from '@/composables/useToast'

const router = useRouter()
const { setAuth } = useAuthStore()
const { theme, toggle } = useTheme()
const toast = useToast()

const form = reactive({ username: '', password: '' })
const loading = ref(false)
const showPassword = ref(false)

const inputClass =
  'w-full rounded-lg border border-slate-200 bg-white py-2.5 pl-10 pr-4 text-sm text-slate-800 placeholder:text-slate-400 outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-100 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200 dark:placeholder:text-slate-500 dark:focus:border-blue-500 dark:focus:ring-blue-500/20'

async function handleLogin() {
  if (loading.value) return
  loading.value = true
  try {
    const data = await authApi.login(form.username, form.password)
    setAuth(data.token, form.username)
    router.push({ name: 'networks' })
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : '登录失败')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="relative flex min-h-screen items-center justify-center overflow-hidden bg-slate-100 px-4 dark:bg-slate-900">
    <!-- 装饰渐变 -->
    <div
      class="pointer-events-none absolute -top-32 -left-32 h-96 w-96 rounded-full bg-blue-200/40 blur-3xl dark:bg-blue-500/20"
    ></div>
    <div
      class="pointer-events-none absolute -right-32 -bottom-32 h-96 w-96 rounded-full bg-indigo-200/40 blur-3xl dark:bg-indigo-500/20"
    ></div>

    <button
      class="absolute right-5 top-5 z-10 flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white/80 px-2.5 py-1.5 text-sm text-slate-500 shadow-sm backdrop-blur transition hover:text-blue-600 dark:border-slate-700 dark:bg-slate-800/80 dark:text-slate-400 dark:hover:text-blue-400"
      :title="theme === 'dark' ? '切换到浅色模式' : '切换到深色模式'"
      @click="toggle"
    >
      <Sun v-if="theme === 'dark'" :size="16" />
      <Moon v-else :size="16" />
    </button>

    <div class="relative w-full max-w-md">
      <div class="mb-6 flex justify-center">
        <AppLogo />
      </div>
      <div class="rounded-2xl border border-slate-200 bg-white p-8 shadow-lg dark:border-slate-700 dark:bg-slate-800">
        <h2 class="mb-1 text-center text-xl font-bold text-slate-900 dark:text-slate-100">登录控制中心</h2>
        <p class="mb-6 text-center text-sm text-slate-400 dark:text-slate-500">请输入管理员账号信息</p>

        <form class="space-y-4" @submit.prevent="handleLogin">
          <div>
            <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">用户名</label>
            <div class="relative">
              <User :size="16" class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
              <input
                v-model.trim="form.username"
                type="text"
                :class="inputClass"
                placeholder="请输入用户名"
                autocomplete="username"
                required
              />
            </div>
          </div>

          <div>
            <label class="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300">密码</label>
            <div class="relative">
              <Lock :size="16" class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
              <input
                v-model="form.password"
                :type="showPassword ? 'text' : 'password'"
                :class="inputClass"
                placeholder="请输入密码"
                autocomplete="current-password"
                required
              />
              <button
                type="button"
                class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 transition hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300"
                @click="showPassword = !showPassword"
              >
                <EyeOff v-if="showPassword" :size="16" />
                <Eye v-else :size="16" />
              </button>
            </div>
          </div>

          <button
            type="submit"
            :disabled="loading"
            class="flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <LoaderCircle v-if="loading" :size="16" class="animate-spin" />
            {{ loading ? '登录中...' : '登 录' }}
          </button>
        </form>
      </div>
      <p class="mt-4 text-center text-xs text-slate-400 dark:text-slate-500">vnt 服务端管理控制台</p>
    </div>
  </div>
</template>