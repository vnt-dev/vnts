<script setup lang="ts">
import { Gauge, Server, Trash2 } from '@lucide/vue'
import type { PeerServerInfo } from '@/types'

defineProps<{ server: PeerServerInfo; direction: 'outbound' | 'inbound' }>()

const emit = defineEmits<{ remove: [] }>()
</script>

<template>
  <div
    class="flex flex-col rounded-xl border p-4 shadow-sm transition"
    :class="server.connected ? 'border-emerald-200 bg-emerald-50/50' : 'border-slate-200 bg-white'"
  >
    <div class="flex items-start justify-between gap-2">
      <div class="flex min-w-0 items-center gap-2.5">
        <div
          class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-white"
          :class="direction === 'outbound' ? 'bg-blue-500' : 'bg-purple-500'"
        >
          <Server :size="17" />
        </div>
        <div class="min-w-0">
          <div class="truncate font-mono text-sm font-semibold text-slate-800">{{ server.addr }}</div>
          <div class="mt-0.5 flex items-center gap-1.5 text-xs">
            <span
              class="inline-flex items-center gap-1 font-medium"
              :class="server.connected ? 'text-emerald-600' : 'text-slate-400'"
            >
              <span
                class="h-1.5 w-1.5 rounded-full"
                :class="server.connected ? 'bg-emerald-500' : 'bg-slate-300'"
              ></span>
              {{ server.connected ? '在线' : '离线' }}
            </span>
          </div>
        </div>
      </div>
      <button
        class="shrink-0 rounded-lg p-1.5 text-slate-400 transition hover:bg-red-50 hover:text-red-600"
        title="删除"
        @click="emit('remove')"
      >
        <Trash2 :size="15" />
      </button>
    </div>

    <div class="mt-3 flex items-center gap-1.5 border-t border-slate-100 pt-3 text-xs text-slate-500">
      <Gauge :size="13" class="shrink-0 text-slate-400" />
      延迟
      <span class="font-semibold tabular-nums text-slate-700">{{ server.latency_ms }} ms</span>
    </div>
  </div>
</template>