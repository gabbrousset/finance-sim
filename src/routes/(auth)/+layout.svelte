<script lang="ts">
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
  let { children } = $props();
</script>

<header class="flex items-center justify-between p-6">
  <a href="/" class="font-semibold">finance-sim</a>
  <ThemeToggle />
</header>
<main class="mx-auto max-w-md px-6 py-12">
  {@render children()}
</main>
