<script lang="ts">
  import { enhance } from '$app/forms';
  import TextField from '$lib/components/forms/TextField.svelte';
  import FormError from '$lib/components/forms/FormError.svelte';
  import Button from '$lib/components/Button.svelte';
  import type { PageProps } from './$types';

  let { data, form }: PageProps = $props();

  let displayName = $state('');
  let errorMsg = $derived((form as { error?: string } | null)?.error ?? '');

  $effect(() => {
    if (data.user?.displayName) displayName = data.user.displayName;
  });
</script>

<h1 class="text-2xl font-bold">settings</h1>

<section class="mt-8 max-w-md">
  <h2 class="mb-4 text-lg font-semibold">account</h2>

  <div class="mb-4">
    <p class="text-sm font-medium text-zinc-700 dark:text-zinc-300">username</p>
    <p class="mt-1 text-sm text-zinc-500">{data.user.username}</p>
  </div>

  <form method="POST" action="?/updateDisplayName" use:enhance class="flex flex-col gap-4">
    <TextField name="displayName" label="display name" bind:value={displayName} />
    <FormError message={errorMsg} />
    {#if (form as { ok?: boolean } | null)?.ok}
      <p class="text-sm text-green-600 dark:text-green-400">display name updated</p>
    {/if}
    <Button type="submit" variant="primary">save</Button>
  </form>
</section>

<section class="mt-10 max-w-md">
  <h2 class="mb-2 text-lg font-semibold">security</h2>
  <p class="text-sm text-zinc-500">manage your passkeys and recovery codes.</p>
  <a
    href="/settings/passkeys"
    class="mt-3 inline-flex items-center text-sm font-medium underline-offset-2 hover:underline"
  >
    manage passkeys →
  </a>
</section>
