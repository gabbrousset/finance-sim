<script lang="ts">
  import { enhance } from '$app/forms';
  import { deserialize } from '$app/forms';
  import { startAuthentication } from '@simplewebauthn/browser';
  import Button from '$lib/components/Button.svelte';
  import FormError from '$lib/components/forms/FormError.svelte';
  import type { PageProps } from './$types';

  let { form }: PageProps = $props();

  let stage: 'idle' | 'authenticating' | 'done' = $state('idle');
  let errorMsg = $state('');

  async function runSignin(options: unknown) {
    try {
      const assertion = await startAuthentication({
        optionsJSON: options as Parameters<typeof startAuthentication>[0]['optionsJSON'],
        useBrowserAutofill: false
      });
      const formData = new FormData();
      formData.append('assertion', JSON.stringify(assertion));
      const res = await fetch('/signin?/complete', {
        method: 'POST',
        headers: { 'x-sveltekit-action': 'true' },
        body: formData
      });
      const result = deserialize(await res.text());
      if (result.type === 'success') {
        stage = 'done';
        window.location.href = '/portfolio';
      } else if (result.type === 'failure' && result.data) {
        const data = result.data as { error?: string };
        errorMsg = data.error ?? 'sign-in failed';
        stage = 'idle';
      } else {
        errorMsg = 'sign-in failed';
        stage = 'idle';
      }
    } catch (e) {
      errorMsg = e instanceof Error ? e.message : 'passkey authentication failed';
      stage = 'idle';
    }
  }
</script>

<h1 class="text-3xl font-bold">sign in</h1>
<p class="mt-2 text-sm text-zinc-500">use your passkey to sign in.</p>

{#if stage === 'idle' || stage === 'authenticating'}
  <form
    method="POST"
    action="?/begin"
    use:enhance={() => {
      errorMsg = '';
      stage = 'authenticating';
      return async ({ result }) => {
        if (result.type === 'failure') {
          const data = result.data as { error?: string } | undefined;
          errorMsg = data?.error ?? 'sign-in failed';
          stage = 'idle';
        } else if (result.type === 'success' && result.data) {
          const data = result.data as { stage: string; options: unknown };
          if (data.stage === 'options') {
            await runSignin(data.options);
          }
        }
      };
    }}
    class="mt-8 flex flex-col gap-4"
  >
    <FormError message={errorMsg} />
    <Button type="submit" variant="primary" disabled={stage === 'authenticating'}>
      {stage === 'authenticating' ? 'waiting for passkey...' : 'sign in with passkey'}
    </Button>
  </form>
  <p class="mt-4 text-sm text-zinc-500">
    <a href="/recover" class="underline hover:text-zinc-700 dark:hover:text-zinc-300">
      use a recovery code
    </a>
  </p>
{:else if stage === 'done'}
  <p class="mt-8 text-zinc-600 dark:text-zinc-400">signing you in...</p>
{/if}
