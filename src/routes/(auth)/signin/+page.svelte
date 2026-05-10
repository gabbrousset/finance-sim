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

<h1 class="auth-h">Welcome back.</h1>

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
					if (data.stage === 'options') await runSignin(data.options);
				}
			};
		}}
		class="auth-form"
	>
		<FormError message={errorMsg} />
		<Button type="submit" variant="primary" disabled={stage === 'authenticating'}>
			{stage === 'authenticating' ? 'Awaiting confirmation…' : 'Enter.'}
		</Button>
	</form>
	<p class="auth-foot">
		<a href="/recover">Use a recovery code →</a>
	</p>
{:else if stage === 'done'}
	<p class="auth-deck"><em>Signing you in…</em></p>
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
	.auth-deck {
		font-family: var(--font-body);
		font-style: italic;
		font-size: 14px;
		color: var(--color-ink-2);
		margin: 0 0 24px;
	}
	.auth-form { display: flex; flex-direction: column; gap: 14px; }
	.auth-foot {
		margin-top: 18px;
		font-family: var(--font-body);
		font-size: 14px;
	}
	.auth-foot a {
		color: var(--color-ink-2);
		border-bottom: 1px dotted var(--color-rule);
		text-decoration: none;
	}
	.auth-foot a:hover { color: var(--color-ink); }
</style>
