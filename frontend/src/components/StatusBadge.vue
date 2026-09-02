<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ status?: string }>()

const config = computed(() => {
  switch (props.status) {
    case 'Online':
      return {
        label: '在线',
        dot: 'bg-emerald-500',
        cls: 'bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:ring-emerald-500/30',
      }
    case 'Remote':
      return {
        label: '远程',
        dot: 'bg-blue-500',
        cls: 'bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-500/10 dark:text-blue-400 dark:ring-blue-500/30',
      }
    default:
      return {
        label: '离线',
        dot: 'bg-red-400',
        cls: 'bg-red-50 text-red-600 ring-red-200 dark:bg-red-500/10 dark:text-red-400 dark:ring-red-500/30',
      }
  }
})
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset"
    :class="config.cls"
  >
    <span class="h-1.5 w-1.5 rounded-full" :class="config.dot"></span>
    {{ config.label }}
  </span>
</template>