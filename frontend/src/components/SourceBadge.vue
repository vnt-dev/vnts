<script setup lang="ts">
import { computed } from 'vue'
import { formatSource, sourceBadgeClass } from '@/utils/format'

const props = defineProps<{ source?: string }>()

const cls = computed(() => sourceBadgeClass(props.source))
const label = computed(() => formatSource(props.source))
</script>

<template>
  <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset" :class="cls">
    {{ label }}
  </span>
</template>