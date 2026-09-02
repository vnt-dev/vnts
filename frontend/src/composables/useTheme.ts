import { ref } from 'vue'

const THEME_KEY = 'vnt_theme'

export type Theme = 'light' | 'dark'

function storedTheme(): Theme | null {
  const v = localStorage.getItem(THEME_KEY)
  return v === 'light' || v === 'dark' ? v : null
}

function systemTheme(): Theme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function applyTheme(t: Theme) {
  theme.value = t
  document.documentElement.classList.toggle('dark', t === 'dark')
  document.documentElement.style.colorScheme = t
}

// 模块级单例状态，各组件共享
const theme = ref<Theme>(storedTheme() ?? systemTheme())

applyTheme(theme.value)

export function useTheme() {
  function toggle() {
    const next: Theme = theme.value === 'dark' ? 'light' : 'dark'
    applyTheme(next)
    localStorage.setItem(THEME_KEY, next)
  }

  return { theme, toggle }
}