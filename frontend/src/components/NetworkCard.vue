<script setup lang="ts">
import { ArrowRight, Clock, Globe, Pencil, Server, Trash2 } from '@lucide/vue'
import { computed } from 'vue'
import SourceBadge from './SourceBadge.vue'
import type { NetworkInfo } from '@/types'
import { formatDuration } from '@/utils/format'

const props = defineProps<{ network: NetworkInfo }>()
const emit = defineEmits<{ select: []; edit: []; remove: [] }>()

const onlineRatio = computed(() =>
  props.network.all_count > 0
    ? Math.round((props.network.online_count / props.network.all_count) * 100)
    : 0,
)
</script>

<template>
  <div
    class="group flex cursor-pointer flex-col rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition hover:-translate-y-0.5 hover:border-blue-200 hover:shadow-md"
    @click="emit('select')"
  >
    <div class="flex items-start justify-between gap-3">
      <div class="min-w-0">
        <h3 class="truncate text-base font-bold text-slate-900 group-hover:text-blue-700">
          {{ network.network_code }}
        </h3>
        <p class="mt-0.5 font-mono text-sm text-slate-500">{{ network.net }}</p>
      </div>
      <div class="flex shrink-0 items-center gap-1">
        <button
          class="rounded-lg p-1.5 text-slate-400 transition hover:bg-blue-50 hover:text-blue-600"
          title="编辑"
          @click.stop="emit('edit')"
        >
          <Pencil :size="15" />
        </button>
        <button
          class="rounded-lg p-1.5 text-slate-400 transition hover:bg-red-50 hover:text-red-600"
          title="删除"
          @click.stop="emit('remove')"
        >
          <Trash2 :size="15" />
        </button>
      </div>
    </div>

    <div class="mt-3 space-y-1.5 text-xs text-slate-500">
      <div class="flex items-center gap-1.5">
        <Server :size="13" class="shrink-0 text-slate-400" />
        网关
        <span class="font-mono font-medium text-slate-700">{{ network.gateway }}</span>
        <span class="text-slate-400">/ {{ network.netmask }}</span>
      </div>
      <div class="flex items-center gap-1.5">
        <Clock :size="13" class="shrink-0 text-slate-400" />
        租期
        <span class="font-medium text-slate-700">{{ formatDuration(network.lease_duration) }}</span>
      </div>
      <div class="flex items-center gap-1.5">
        <Globe :size="13" class="shrink-0 text-slate-400" />
        类型
        <span class="font-medium" :class="network.network_type === 'Private' ? 'text-amber-600' : 'text-emerald-600'">
          {{ network.network_type === 'Private' ? '私有' : '公开' }}
        </span>
      </div>
      <div class="flex items-center gap-1.5">
        <Globe :size="13" class="shrink-0 text-slate-400" />
        来源
        <SourceBadge :source="network.source" />
      </div>
    </div>

    <div class="mt-4 border-t border-slate-100 pt-3">
      <div class="flex items-center justify-between text-xs">
        <span class="font-semibold text-slate-700">
          {{ network.online_count }}
          <span class="font-normal text-slate-400">/ {{ network.all_count }} 在线</span>
        </span>
        <span class="flex items-center gap-1 text-blue-600 opacity-60 transition group-hover:opacity-100">
          查看设备
          <ArrowRight :size="13" />
        </span>
      </div>
      <div class="mt-1.5 h-1.5 overflow-hidden rounded-full bg-slate-100">
        <div
          class="h-full rounded-full bg-blue-500 transition-all duration-500"
          :style="{ width: `${onlineRatio}%` }"
        ></div>
      </div>
    </div>
  </div>
</template>
