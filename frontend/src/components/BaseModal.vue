<script setup lang="ts">
import { X } from '@lucide/vue'

defineProps<{
  open: boolean
  title?: string
}>()

const emit = defineEmits<{ close: [] }>()
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div class="absolute inset-0 bg-slate-900/40" @click="emit('close')"></div>
        <div class="relative w-full max-w-md rounded-2xl bg-white shadow-2xl dark:bg-slate-800">
          <div v-if="title" class="flex items-center justify-between border-b border-slate-100 px-6 py-4 dark:border-slate-700">
            <h3 class="text-base font-bold text-slate-900 dark:text-slate-100">{{ title }}</h3>
            <button
              class="rounded-lg p-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-600 dark:text-slate-500 dark:hover:bg-slate-700 dark:hover:text-slate-300"
              @click="emit('close')"
            >
              <X :size="18" />
            </button>
          </div>
          <div class="px-6 py-5">
            <slot />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.modal-enter-active {
  animation: modal-in 0.18s ease-out;
}
.modal-leave-active {
  animation: modal-out 0.15s ease-in forwards;
}
@keyframes modal-in {
  from {
    opacity: 0;
    transform: scale(0.97) translateY(8px);
  }
  to {
    opacity: 1;
    transform: none;
  }
}
@keyframes modal-out {
  from {
    opacity: 1;
    transform: none;
  }
  to {
    opacity: 0;
    transform: scale(0.97) translateY(8px);
  }
}
</style>