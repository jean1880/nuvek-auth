<script setup lang="ts">
import { watchEffect } from 'vue'
import { useAuth } from './useAuth'

const props = withDefaults(defineProps<{ autoLogin?: boolean }>(), { autoLogin: true })

const { isLoading, isAuthenticated, error, login } = useAuth()
const signIn = () => login()

// Signed out → redirect to Auth0 at once. A top-level redirect carries Auth0's first-party session
// cookie, so a live session returns without a prompt. After a failed login (error set), stay on
// the unauthenticated slot instead of looping.
watchEffect(() => {
  if (props.autoLogin && !isLoading.value && !isAuthenticated.value && !error.value) void signIn()
})
</script>

<template>
  <slot v-if="isLoading" name="loading" />
  <slot v-else-if="isAuthenticated" :login="signIn" />
  <slot v-else name="unauthenticated" :login="signIn" />
</template>
