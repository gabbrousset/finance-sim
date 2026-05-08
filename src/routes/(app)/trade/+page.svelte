<script lang="ts">
	import { enhance } from '$app/forms';
	import TextField from '$lib/components/forms/TextField.svelte';
	import Button from '$lib/components/Button.svelte';
	import FormError from '$lib/components/forms/FormError.svelte';
	import { formatUsd } from '$lib/shared/money';

	let { data, form } = $props();

	let mode: 'buy' | 'sell' = $state('buy');
	let symbol = $state('');
	let shares = $state('');

	// Repopulate from form prop on validation failures (form prop changes
	// after each submit). Skip on success — we want to clear shares instead.
	$effect(() => {
		if (form?.success) {
			shares = '';
			return;
		}
		if (form && 'symbol' in form && typeof form.symbol === 'string') {
			symbol = form.symbol;
		}
		if (form && 'shares' in form && form.shares != null) {
			shares = String(form.shares);
		}
	});
</script>

<h1 class="text-2xl font-semibold">trade</h1>

<div class="mt-4 text-sm text-zinc-500">
	cash: <span class="mono tabular">{formatUsd(data.cashCents)}</span>
</div>

<div class="mt-6 inline-flex rounded-md border border-zinc-200 dark:border-zinc-800">
	<button
		type="button"
		onclick={() => (mode = 'buy')}
		class="px-4 py-2 text-sm {mode === 'buy' ? 'bg-zinc-900 text-white dark:bg-white dark:text-zinc-900' : ''}"
	>buy</button>
	<button
		type="button"
		onclick={() => (mode = 'sell')}
		class="px-4 py-2 text-sm {mode === 'sell' ? 'bg-zinc-900 text-white dark:bg-white dark:text-zinc-900' : ''}"
	>sell</button>
</div>

<form method="POST" use:enhance class="mt-6 flex flex-col gap-4 max-w-sm">
	<input type="hidden" name="mode" value={mode} />
	<TextField name="symbol" label="symbol" bind:value={symbol} required />
	<TextField name="shares" label="shares" type="number" bind:value={shares} required />
	<FormError message={form?.error ?? ''} />
	{#if form?.success}
		<p class="rounded-md bg-emerald-50 p-3 text-sm text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200">
			{form.message} <a href="/portfolio" class="underline">view portfolio</a>
		</p>
	{/if}
	<Button type="submit" variant="primary">{mode}</Button>
</form>

{#if mode === 'sell' && data.holdings.length > 0}
	<div class="mt-8">
		<div class="text-xs text-zinc-500">your holdings</div>
		<ul class="mt-2 space-y-1 text-sm">
			{#each data.holdings as h}
				<li class="flex gap-3">
					<button
						type="button"
						onclick={() => (symbol = h.symbol)}
						class="font-mono underline-offset-4 hover:underline"
					>{h.symbol}</button>
					<span class="tabular text-zinc-500">{h.shares} shares</span>
				</li>
			{/each}
		</ul>
	</div>
{/if}
