<script setup lang="ts">
import { AlertTriangle, LoaderCircle } from '@lucide/vue'
import BaseModal from './BaseModal.vue'

defineProps<{
  open: boolean
  message: string
  loading?: boolean
}>()

const emit = defineEmits<{ confirm: []; close: [] }>()
</script>

<template>
  <BaseModal :open="open" @close="emit('close')">
    <div class="flex items-start gap-4">
      <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-red-50">
        <AlertTriangle class="text-red-500" :size="20" />
      </div>
      <p class="pt-1.5 text-sm leading-relaxed text-slate-600">{{ message }}</p>
    </div>
    <div class="mt-6 flex justify-end gap-3">
      <button
        class="rounded-lg px-4 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 disabled:opacity-50"
        :disabled="loading"
        @click="emit('close')"
      >
        取消
      </button>
      <button
        class="flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-red-700 disabled:opacity-60"
        :disabled="loading"
        @click="emit('confirm')"
      >
        <LoaderCircle v-if="loading" :size="15" class="animate-spin" />
        {{ loading ? '处理中...' : '确认删除' }}
      </button>
    </div>
  </BaseModal>
</template>