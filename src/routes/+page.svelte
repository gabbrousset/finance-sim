<script lang="ts">
  import { ArrowRight } from 'lucide-svelte';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
</script>

<header class="flex items-center justify-between p-6">
  <span class="font-semibold">finance-sim</span>
  <ThemeToggle />
</header>

<main class="mx-auto max-w-2xl px-6 py-24">
  <h1 class="text-5xl font-bold tracking-tight">paper trading + competitions.</h1>
  <p class="mt-4 text-lg text-zinc-600 dark:text-zinc-400">
    track a fake portfolio. run instant-replay competitions on past windows. or compete live with your friends.
    passkey sign-in. no email.
  </p>
  <div class="mt-8 flex gap-3">
    <a href="/signup" class="rounded-md bg-zinc-900 px-4 py-2 text-white dark:bg-white dark:text-zinc-900">
      sign up <ArrowRight class="inline h-4 w-4" />
    </a>
    <a href="/signin" class="rounded-md border border-zinc-300 px-4 py-2 dark:border-zinc-700">
      sign in
    </a>
  </div>
</main>
