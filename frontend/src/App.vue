<script setup lang="ts">
import AppSidebar from './components/AppSidebar.vue'
import AppTopbar from './components/AppTopbar.vue'
import ToastHost from './components/ToastHost.vue'
import { useAuthStore } from './composables/useAuth'

const { isLoggedIn } = useAuthStore()
</script>

<template>
  <div class="min-h-screen">
    <template v-if="isLoggedIn">
      <div class="flex min-h-screen">
        <AppSidebar />
        <div class="flex min-w-0 flex-1 flex-col lg:pl-56">
          <AppTopbar />
          <main class="mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 sm:px-6 lg:px-8">
            <RouterView v-slot="{ Component }">
              <Transition name="fade" mode="out-in">
                <component :is="Component" />
              </Transition>
            </RouterView>
          </main>
        </div>
      </div>
    </template>
    <RouterView v-else />
    <ToastHost />
  </div>
</template>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>