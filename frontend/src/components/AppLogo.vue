<script setup lang="ts">
import { Network } from '@lucide/vue'
</script>

<template>
  <div class="flex items-center gap-2.5">
    <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-600 text-white shadow-sm">
      <Network :size="20" :stroke-width="2" />
    </div>
    <div class="leading-tight">
      <div class="text-[15px] font-bold text-slate-900">vnt 控制中心</div>
      <div class="text-[11px] text-slate-400">Virtual Network Tool</div>
    </div>
  </div>
</template>