<script setup lang="ts">
import { useAuth } from './useAuth'

const { isLoading, isAuthenticated, login } = useAuth()
const signIn = () => login()
</script>

<template>
  <slot v-if="isLoading" name="loading" />
  <slot v-else-if="isAuthenticated" :login="signIn" />
  <slot v-else name="unauthenticated" :login="signIn" />
</template>
