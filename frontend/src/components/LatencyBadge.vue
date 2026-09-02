<script setup lang="ts">
import { computed } from 'vue'
import { latencyLevel, latencyTextClass } from '@/utils/format'

const props = defineProps<{ ms: number | null | undefined }>()

const level = computed(() => latencyLevel(props.ms))
const cls = computed(() => latencyTextClass(level.value))
</script>

<template>
  <span
    v-if="props.ms !== null && props.ms !== undefined"
    class="font-semibold tabular-nums"
    :class="cls"
  >
    {{ props.ms }} ms
  </span>
  <span v-else class="text-slate-400 dark:text-slate-500">-</span>
</template>