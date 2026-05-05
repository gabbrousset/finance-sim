<script lang="ts">
  import { enhance } from '$app/forms';
  import TextField from '$lib/components/forms/TextField.svelte';
  import Button from '$lib/components/Button.svelte';
  import FormError from '$lib/components/forms/FormError.svelte';
  import type { PageProps } from './$types';

  let { form }: PageProps = $props();
</script>

<h1 class="text-3xl font-bold">recover account</h1>
<p class="mt-2 text-sm text-zinc-500">
  enter your username and a recovery code to regain access.
</p>

<form method="POST" use:enhance class="mt-8 flex flex-col gap-4">
  <TextField name="username" label="username" required autocomplete="username" />
  <TextField name="code" label="recovery code" required autocomplete="off" />
  <FormError message={form?.error ?? ''} />
  <Button type="submit" variant="primary">recover account</Button>
</form>

<p class="mt-4 text-sm text-zinc-500">
  <a href="/signin" class="underline hover:text-zinc-700 dark:hover:text-zinc-300">
    back to sign in
  </a>
</p>
