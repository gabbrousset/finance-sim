<script lang="ts">
	import { enhance } from '$app/forms';
	import TextField from '$lib/components/forms/TextField.svelte';
	import Button from '$lib/components/Button.svelte';
	import FormError from '$lib/components/forms/FormError.svelte';
	import Sparkline from '$lib/components/charts/Sparkline.svelte';
	import { formatUsd } from '$lib/shared/money';

	let { form } = $props();
	let symbol = $state(form?.symbol ?? '');
	let sparkData = $state<number[] | null>(null);
	let sparkDates = $state<string[] | undefined>();

	// When the form action returns a successful quote, fetch the sparkline.
	$effect(() => {
		if (form?.symbol && !form?.error) {
			fetch(`/api/sparkline/${form.symbol}`)
				.then((r) => (r.ok ? r.json() : null))
				.then((j) => {
					if (j) {
						sparkData = j.closes;
						sparkDates = j.dates;
					}
				});
		}
	});
</script>

<h1 class="text-2xl font-semibold">quote</h1>

<form method="POST" use:enhance class="mt-6 flex max-w-sm flex-col gap-3">
	<TextField name="symbol" label="symbol" bind:value={symbol} required />
	<FormError message={form?.error ?? ''} />
	<Button type="submit" variant="primary">get quote</Button>
</form>

{#if form?.priceCents != null && !form?.error}
	<div class="mt-8 max-w-sm rounded-md border border-zinc-200 p-6 dark:border-zinc-800">
		<div class="text-xs text-zinc-500">{form.symbol}</div>
		<div class="mono mt-1 text-3xl tabular">{formatUsd(form.priceCents)}</div>
		{#if sparkData}
			<div class="mt-4">
				<Sparkline data={sparkData} dates={sparkDates} />
			</div>
		{/if}
	</div>
{/if}
