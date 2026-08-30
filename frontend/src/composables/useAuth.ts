import { computed, ref } from 'vue'

const TOKEN_KEY = 'jwt_token'
const USERNAME_KEY = 'username'

// 模块级单例状态，路由守卫与各组件共享
const token = ref<string>(localStorage.getItem(TOKEN_KEY) ?? '')
const username = ref<string>(localStorage.getItem(USERNAME_KEY) ?? '')

export function useAuthStore() {
  const isLoggedIn = computed(() => token.value.length > 0)

  function setAuth(newToken: string, newUsername: string) {
    token.value = newToken
    username.value = newUsername
    localStorage.setItem(TOKEN_KEY, newToken)
    localStorage.setItem(USERNAME_KEY, newUsername)
  }

  function logout() {
    token.value = ''
    username.value = ''
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USERNAME_KEY)
  }

  return { token, username, isLoggedIn, setAuth, logout }
}