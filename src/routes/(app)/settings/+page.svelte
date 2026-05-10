<script lang="ts">
	import { enhance } from '$app/forms';
	import TextField from '$lib/components/forms/TextField.svelte';
	import FormError from '$lib/components/forms/FormError.svelte';
	import Button from '$lib/components/Button.svelte';
	import SectionHead from '$lib/components/marks/SectionHead.svelte';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();
	let displayName = $state('');
	let errorMsg = $derived((form as { error?: string } | null)?.error ?? '');

	$effect(() => {
		if (data.user?.displayName) displayName = data.user.displayName;
	});
</script>

<SectionHead eyebrow="VI — Settings" title="Settings." />

<section class="sec">
	<h2 class="sub">Particulars</h2>
	<p class="line"><span class="lbl">Username</span> <span class="val">{data.user.username}</span></p>
	<form method="POST" action="?/updateDisplayName" use:enhance class="form">
		<TextField name="displayName" label="Display name" bind:value={displayName} />
		<FormError message={errorMsg} />
		{#if (form as { ok?: boolean } | null)?.ok}
			<p class="ok"><em>Display name updated.</em></p>
		{/if}
		<Button type="submit" variant="primary">Save</Button>
	</form>
</section>

<section class="sec">
	<h2 class="sub">Keys</h2>
	<p class="prose">Devices and recovery codes on file.</p>
	<a href="/settings/passkeys" class="link">Keys on file →</a>
</section>

<style>
	.sec { margin-top: 28px; max-width: 460px; }
	.sub {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 60, 'wght' 500;
		font-size: 22px;
		margin: 0 0 12px;
		letter-spacing: -0.01em;
	}
	.line { font-family: var(--font-body); font-size: 14px; margin: 0 0 14px; }
	.line .lbl {
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-3);
		margin-right: 8px;
	}
	.form { display: flex; flex-direction: column; gap: 14px; }
	.ok { font-family: var(--font-body); color: var(--color-gain); margin: 0; }
	.prose { font-family: var(--font-body); color: var(--color-ink-2); margin: 0 0 8px; }
	.link {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 600;
		font-size: 14px;
		color: var(--color-ink);
		border-bottom: 1px solid var(--color-rule);
		text-decoration: none;
	}
	.link:hover { color: var(--color-stamp); }
</style>
