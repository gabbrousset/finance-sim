<script lang="ts">
  import { enhance } from '$app/forms';
  import { deserialize } from '$app/forms';
  import { startRegistration } from '@simplewebauthn/browser';
  import TextField from '$lib/components/forms/TextField.svelte';
  import Button from '$lib/components/Button.svelte';
  import FormError from '$lib/components/forms/FormError.svelte';
  import { Copy, Download } from 'lucide-svelte';
  import type { PageProps } from './$types';

  let { form }: PageProps = $props();

  let stage: 'form' | 'creating' | 'success' = $state('form');
  let recoveryCodes = $state<string[]>([]);
  let codesSaved = $state(false);
  let errorMsg = $state('');

  async function runCreate(options: unknown) {
    try {
      const attestation = await startRegistration({
        optionsJSON: options as Parameters<typeof startRegistration>[0]['optionsJSON']
      });
      const res = await fetch('/signup?/complete', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-sveltekit-action': 'true'
        },
        body: JSON.stringify({ attestation })
      });
      const result = deserialize(await res.text());
      if (result.type === 'success' && result.data) {
        const data = result.data as { stage: string; recoveryCodes: string[] };
        recoveryCodes = data.recoveryCodes ?? [];
        stage = 'success';
      } else if (result.type === 'failure' && result.data) {
        const data = result.data as { error?: string };
        errorMsg = data.error ?? 'signup failed';
        stage = 'form';
      } else {
        errorMsg = 'signup failed';
        stage = 'form';
      }
    } catch (e) {
      errorMsg = e instanceof Error ? e.message : 'passkey creation failed';
      stage = 'form';
    }
  }

  function copy() {
    navigator.clipboard.writeText(recoveryCodes.join('\n'));
  }

  function download() {
    const blob = new Blob([recoveryCodes.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'finance-sim-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  }
</script>

<h1 class="text-3xl font-bold">create your account</h1>
<p class="mt-2 text-sm text-zinc-500">
  no email required. you'll create a passkey and get 8 recovery codes.
</p>

{#if stage === 'form'}
  <form
    method="POST"
    action="?/begin"
    use:enhance={({ formData, cancel }) => {
      errorMsg = '';
      return async ({ result }) => {
        if (result.type === 'failure') {
          const data = result.data as { error?: string } | undefined;
          errorMsg = data?.error ?? 'signup failed';
        } else if (result.type === 'success' && result.data) {
          const data = result.data as { stage: string; options: unknown };
          if (data.stage === 'options') {
            stage = 'creating';
            await runCreate(data.options);
          }
        }
      };
    }}
    class="mt-8 flex flex-col gap-4"
  >
    <TextField name="username" label="username" required />
    <TextField name="displayName" label="display name (optional)" />
    <FormError message={errorMsg} />
    <Button type="submit" variant="primary">continue</Button>
  </form>
{:else if stage === 'creating'}
  <p class="mt-8 text-zinc-600 dark:text-zinc-400">creating your passkey...</p>
{:else if stage === 'success'}
  <h2 class="mt-8 text-xl font-semibold">save your recovery codes</h2>
  <p class="mt-2 text-sm text-zinc-500">
    these are your only fallback if you lose all your passkeys. each works once.
  </p>
  <pre
    class="mt-4 rounded-md bg-zinc-50 p-4 font-mono text-sm dark:bg-zinc-900"
  >{recoveryCodes.join('\n')}</pre>
  <div class="mt-2 flex gap-2">
    <Button variant="ghost" onclick={copy}>
      <Copy class="mr-1 inline h-4 w-4" />copy
    </Button>
    <Button variant="ghost" onclick={download}>
      <Download class="mr-1 inline h-4 w-4" />download
    </Button>
  </div>
  <label class="mt-6 flex items-center gap-2">
    <input type="checkbox" bind:checked={codesSaved} />
    <span class="text-sm">i've saved my recovery codes</span>
  </label>
  <Button
    variant="primary"
    disabled={!codesSaved}
    onclick={() => (window.location.href = '/portfolio')}
    class="mt-4"
  >
    continue to portfolio
  </Button>
{/if}
