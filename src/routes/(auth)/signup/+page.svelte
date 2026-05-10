<script lang="ts">
	import { enhance } from '$app/forms';
	import { deserialize } from '$app/forms';
	import { startRegistration } from '@simplewebauthn/browser';
	import TextField from '$lib/components/forms/TextField.svelte';
	import Button from '$lib/components/Button.svelte';
	import FormError from '$lib/components/forms/FormError.svelte';
	import Stamp from '$lib/components/marks/Stamp.svelte';
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
			const formData = new FormData();
			formData.append('attestation', JSON.stringify(attestation));
			const res = await fetch('/signup?/complete', {
				method: 'POST',
				headers: { 'x-sveltekit-action': 'true' },
				body: formData
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

<h1 class="auth-h">Open an account.</h1>
<p class="auth-deck">
	<em>No email required. You'll create a passkey and get 8 recovery codes.</em>
</p>

{#if stage === 'form'}
	<form
		method="POST"
		action="?/begin"
		use:enhance={() => {
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
		class="auth-form"
	>
		<TextField name="username" label="Username" required />
		<TextField name="displayName" label="Display name (optional)" />
		<FormError message={errorMsg} />
		<Button type="submit" variant="primary">Continue</Button>
	</form>
{:else if stage === 'creating'}
	<p class="auth-deck"><em>Creating your passkey…</em></p>
{:else if stage === 'success'}
	<h2 class="auth-h2">Save your recovery codes.</h2>
	<p class="auth-deck">
		<em>These are your only fallback if you lose all your passkeys. Each works once.</em>
	</p>
	<pre class="codes">{recoveryCodes.join('\n')}</pre>
	<div class="row">
		<Button variant="quiet" onclick={copy}><Copy class="ico" /> Copy</Button>
		<Button variant="quiet" onclick={download}><Download class="ico" /> Download</Button>
	</div>
	<div class="stamp-row">
		<Stamp label="Note these down" size="sm" />
	</div>
	<label class="check">
		<input type="checkbox" bind:checked={codesSaved} />
		<span>I've saved my recovery codes</span>
	</label>
	<Button
		variant="primary"
		disabled={!codesSaved}
		onclick={() => (window.location.href = '/portfolio')}
	>
		Continue to portfolio
	</Button>
{/if}

<style>
	.auth-h {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 96, 'wght' 500;
		font-size: 32px;
		letter-spacing: -0.02em;
		line-height: 1;
		margin: 0 0 4px;
		color: var(--color-ink);
	}
	.auth-h2 {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 60, 'wght' 500;
		font-size: 22px;
		letter-spacing: -0.01em;
		margin: 0 0 4px;
	}
	.auth-deck {
		font-family: var(--font-body);
		font-style: italic;
		font-size: 14px;
		color: var(--color-ink-2);
		margin: 0 0 20px;
	}
	.auth-form { display: flex; flex-direction: column; gap: 14px; }
	.codes {
		font-family: var(--font-mono);
		font-size: 13px;
		background: var(--color-paper-2);
		padding: 14px 18px;
		margin: 0 0 12px;
		line-height: 1.7;
		letter-spacing: 0.04em;
	}
	.row { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
	:global(.row .ico) { width: 14px; height: 14px; margin-right: 4px; }
	.stamp-row {
		display: flex;
		justify-content: flex-end;
		margin: 8px 0 16px;
		padding-right: 14px;
	}
	.check {
		display: flex;
		gap: 8px;
		align-items: center;
		font-family: var(--font-body);
		font-size: 14px;
		color: var(--color-ink);
		margin: 0 0 16px;
	}
</style>
