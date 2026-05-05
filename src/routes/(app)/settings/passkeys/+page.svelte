<script lang="ts">
  import { enhance, deserialize } from '$app/forms';
  import { invalidateAll } from '$app/navigation';
  import { startRegistration } from '@simplewebauthn/browser';
  import Button from '$lib/components/Button.svelte';
  import TextField from '$lib/components/forms/TextField.svelte';
  import FormError from '$lib/components/forms/FormError.svelte';
  import { Cloud, Smartphone, Copy, Download } from 'lucide-svelte';
  import type { PageProps } from './$types';

  let { data, form }: PageProps = $props();

  // --- add passkey flow ---
  type AddStage = 'idle' | 'registering' | 'added';
  let addStage = $state<AddStage>('idle');
  let addError = $state('');

  async function runAddPasskey(options: unknown) {
    try {
      const attestation = await startRegistration({
        optionsJSON: options as Parameters<typeof startRegistration>[0]['optionsJSON']
      });
      const res = await fetch('/settings/passkeys?/completeAdd', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-sveltekit-action': 'true'
        },
        body: JSON.stringify({ attestation })
      });
      const result = deserialize(await res.text());
      if (result.type === 'success') {
        addStage = 'added';
        await invalidateAll();
      } else if (result.type === 'failure' && result.data) {
        const d = result.data as { error?: string };
        addError = d.error ?? 'failed to add passkey';
        addStage = 'idle';
      } else {
        addError = 'failed to add passkey';
        addStage = 'idle';
      }
    } catch (e) {
      addError = e instanceof Error ? e.message : 'passkey registration failed';
      addStage = 'idle';
    }
  }

  // --- inline rename ---
  let editingId = $state<string | null>(null);
  let editingName = $state('');

  function startRename(id: string, currentName: string) {
    editingId = id;
    editingName = currentName;
  }

  function cancelRename() {
    editingId = null;
    editingName = '';
  }

  // --- recovery codes ---
  type CodesStage = 'idle' | 'confirm' | 'showing';
  let codesStage = $state<CodesStage>('idle');
  let recoveryCodes = $state<string[]>([]);
  let codesSaved = $state(false);

  $effect(() => {
    const f = form as { recoveryCodes?: string[] } | null;
    if (f?.recoveryCodes && f.recoveryCodes.length > 0) {
      recoveryCodes = f.recoveryCodes;
      codesStage = 'showing';
    }
  });

  function copyRecoveryCodes() {
    navigator.clipboard.writeText(recoveryCodes.join('\n'));
  }

  function downloadRecoveryCodes() {
    const blob = new Blob([recoveryCodes.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'finance-sim-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  }

  // --- helpers ---
  function relativeTime(unixSec: number): string {
    if (!unixSec) return 'never';
    const now = Math.floor(Date.now() / 1000);
    const diff = now - unixSec;
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d ago`;
    return new Date(unixSec * 1000).toISOString().slice(0, 10);
  }

  let revokeError = $derived((form as { error?: string } | null)?.error ?? '');
</script>

<h1 class="text-2xl font-bold">passkeys</h1>

{#if data.forceSetup}
  <div
    class="mt-4 rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-300"
    role="alert"
  >
    you signed in with a recovery code. add a new passkey now to keep your account accessible.
  </div>
{/if}

<!-- passkeys table -->
<section class="mt-8">
  <h2 class="mb-3 text-base font-semibold">your passkeys</h2>

  {#if revokeError && revokeError !== 'display name must be 1-40 chars' && revokeError !== 'device name must be 1-40 chars'}
    <FormError message={revokeError} />
  {/if}

  <div class="overflow-x-auto rounded-md border border-zinc-200 dark:border-zinc-800">
    <table class="w-full text-sm">
      <thead>
        <tr class="border-b border-zinc-200 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-900/50">
          <th class="px-4 py-2 text-left font-medium text-zinc-500">device</th>
          <th class="px-4 py-2 text-left font-medium text-zinc-500">last used</th>
          <th class="px-4 py-2 text-left font-medium text-zinc-500">sync</th>
          <th class="px-4 py-2 text-left font-medium text-zinc-500">actions</th>
        </tr>
      </thead>
      <tbody>
        {#if data.passkeys.length === 0}
          <tr>
            <td colspan="4" class="px-4 py-6 text-center text-zinc-500">no passkeys found</td>
          </tr>
        {:else}
          {#each data.passkeys as pk (pk.id)}
            <tr class="border-b border-zinc-100 last:border-0 dark:border-zinc-900">
              <!-- device name cell -->
              <td class="px-4 py-2">
                {#if editingId === pk.id}
                  <form
                    method="POST"
                    action="?/rename"
                    use:enhance={() => {
                      return async ({ result }) => {
                        if (result.type === 'success') {
                          editingId = null;
                          await invalidateAll();
                        }
                      };
                    }}
                    class="flex items-center gap-2"
                  >
                    <input type="hidden" name="passkeyId" value={pk.id} />
                    <TextField name="deviceName" label="" bind:value={editingName} />
                    <Button type="submit" variant="primary" size="sm">save</Button>
                    <Button type="button" variant="ghost" size="sm" onclick={cancelRename}>
                      cancel
                    </Button>
                  </form>
                {:else}
                  <div>
                    <span class="font-medium">{pk.deviceName}</span>
                    {#if pk.suggestion && pk.suggestion !== pk.deviceName}
                      <span class="ml-1 text-xs text-zinc-400">({pk.suggestion})</span>
                    {/if}
                  </div>
                {/if}
              </td>

              <!-- last used -->
              <td class="px-4 py-2 text-zinc-500">{relativeTime(pk.lastUsedAt)}</td>

              <!-- backup state -->
              <td class="px-4 py-2">
                {#if pk.backupState === 1}
                  <span title="synced across devices" class="inline-flex items-center gap-1 text-blue-500">
                    <Cloud class="h-4 w-4" />
                    <span class="text-xs">synced</span>
                  </span>
                {:else}
                  <span title="this device only" class="inline-flex items-center gap-1 text-zinc-400">
                    <Smartphone class="h-4 w-4" />
                    <span class="text-xs">local</span>
                  </span>
                {/if}
              </td>

              <!-- actions -->
              <td class="px-4 py-2">
                <div class="flex items-center gap-2">
                  {#if editingId !== pk.id}
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onclick={() => startRename(pk.id, pk.deviceName)}
                    >
                      rename
                    </Button>
                  {/if}

                  <form
                    method="POST"
                    action="?/revoke"
                    use:enhance={({ cancel }) => {
                      if (
                        !confirm(
                          `revoke "${pk.deviceName}"? you'll need another passkey or recovery code to sign in.`
                        )
                      ) {
                        cancel();
                        return;
                      }
                      return async ({ result }) => {
                        if (result.type === 'success') {
                          await invalidateAll();
                        }
                      };
                    }}
                  >
                    <input type="hidden" name="passkeyId" value={pk.id} />
                    <Button type="submit" variant="danger" size="sm">revoke</Button>
                  </form>
                </div>
              </td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>
</section>

<!-- add passkey -->
<section class="mt-8">
  <h2 class="mb-3 text-base font-semibold">add a passkey</h2>

  {#if addStage === 'registering'}
    <p class="text-sm text-zinc-500">follow your device's prompt to create a passkey...</p>
  {:else if addStage === 'added'}
    <p class="text-sm text-green-600 dark:text-green-400">passkey added successfully.</p>
    <Button
      type="button"
      variant="ghost"
      size="sm"
      class="mt-2"
      onclick={() => {
        addStage = 'idle';
      }}
    >
      add another
    </Button>
  {:else}
    <FormError message={addError} />
    <form
      method="POST"
      action="?/beginAdd"
      use:enhance={() => {
        addError = '';
        return async ({ result }) => {
          if (result.type === 'failure') {
            const d = result.data as { error?: string } | undefined;
            addError = d?.error ?? 'failed to begin passkey registration';
          } else if (result.type === 'success' && result.data) {
            const d = result.data as { stage: string; options: unknown };
            if (d.stage === 'options') {
              addStage = 'registering';
              await runAddPasskey(d.options);
            }
          }
        };
      }}
      class="mt-2"
    >
      <Button type="submit" variant="secondary">add a passkey on this device</Button>
    </form>
  {/if}
</section>

<!-- recovery codes -->
<section class="mt-10">
  <h2 class="mb-2 text-base font-semibold">recovery codes</h2>

  {#if codesStage === 'showing'}
    <p class="mb-2 text-sm text-zinc-500">
      save these codes. each works once. these replace your previous codes.
    </p>
    <pre
      class="rounded-md bg-zinc-50 p-4 font-mono text-sm dark:bg-zinc-900"
    >{recoveryCodes.join('\n')}</pre>
    <div class="mt-2 flex gap-2">
      <Button variant="ghost" size="sm" onclick={copyRecoveryCodes}>
        <Copy class="mr-1 inline h-4 w-4" />copy
      </Button>
      <Button variant="ghost" size="sm" onclick={downloadRecoveryCodes}>
        <Download class="mr-1 inline h-4 w-4" />download
      </Button>
    </div>
    <label class="mt-4 flex items-center gap-2">
      <input type="checkbox" bind:checked={codesSaved} />
      <span class="text-sm">i've saved my recovery codes</span>
    </label>
    <Button
      variant="primary"
      size="sm"
      disabled={!codesSaved}
      onclick={() => {
        codesStage = 'idle';
        codesSaved = false;
      }}
      class="mt-3"
    >
      done
    </Button>
  {:else if codesStage === 'confirm'}
    <p class="mb-3 text-sm text-zinc-500">
      this will invalidate all existing recovery codes and generate 8 new ones.
    </p>
    <div class="flex gap-2">
      <form
        method="POST"
        action="?/regenerateCodes"
        use:enhance={() => {
          return async ({ result }) => {
            if (result.type === 'failure') {
              codesStage = 'idle';
            }
            // $effect watches form.recoveryCodes and transitions to 'showing'
          };
        }}
      >
        <Button type="submit" variant="danger" size="sm">yes, regenerate</Button>
      </form>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        onclick={() => {
          codesStage = 'idle';
        }}
      >
        cancel
      </Button>
    </div>
  {:else}
    <p class="mb-3 text-sm text-zinc-500">
      regenerate all recovery codes. your current codes will stop working immediately.
    </p>
    <Button
      type="button"
      variant="secondary"
      size="sm"
      onclick={() => {
        codesStage = 'confirm';
      }}
    >
      regenerate recovery codes
    </Button>
  {/if}
</section>
