<script lang="ts">
	import { enhance } from '$app/forms';
	import TextField from '$lib/components/forms/TextField.svelte';
	import Button from '$lib/components/Button.svelte';
	import FormError from '$lib/components/forms/FormError.svelte';
	import SectionHead from '$lib/components/marks/SectionHead.svelte';
	import Sparkline from '$lib/components/charts/Sparkline.svelte';
	import Stamp from '$lib/components/marks/Stamp.svelte';
	import { formatUsd } from '$lib/shared/money';

	let { form } = $props();
	let symbol = $state('');
	let sparkData = $state<number[] | null>(null);
	let sparkDates = $state<string[] | undefined>();

	$effect(() => {
		if (form && 'symbol' in form && typeof form.symbol === 'string') {
			symbol = form.symbol as string;
		}
	});

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

	const dollars = $derived(
		form?.priceCents != null ? Math.floor(form.priceCents / 100) : null
	);
	const cents = $derived(
		form?.priceCents != null ? `.${(form.priceCents % 100).toString().padStart(2, '0')}` : null
	);
</script>

<SectionHead eyebrow="III — Quote" title="Quote." meta="Last reported close" />

<form method="POST" use:enhance class="qf">
	<TextField name="symbol" label="Symbol" bind:value={symbol} required />
	<FormError message={form?.error ?? ''} />
	<Button type="submit" variant="primary">Get quote</Button>
</form>

{#if form?.priceCents != null && !form?.error}
	<article class="card">
		<div class="sym">{form.symbol}</div>
		<div class="price tabular">
			${dollars?.toLocaleString()}<span class="c">{cents}</span>
		</div>
		{#if sparkData}
			<div class="spark">
				<Sparkline data={sparkData} dates={sparkDates} width={400} height={48} />
			</div>
		{/if}
		<div class="foot">30-day chart · drawn at close</div>
	</article>
{:else if form?.error}
	<div class="error-card">
		<div class="error-card__sym">{form.symbol ?? '—'}</div>
		<Stamp label="No record" variant="loss" size="md" />
	</div>
{/if}

<style>
	.qf {
		display: flex;
		flex-direction: column;
		gap: 14px;
		max-width: 400px;
	}
	.card {
		margin-top: 32px;
		max-width: 460px;
		padding: 20px 24px 18px;
		background: var(--color-paper-receipt);
		box-shadow: 0 14px 28px -22px rgba(22, 17, 10, 0.18);
	}
	.sym {
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.18em;
		text-transform: uppercase;
		color: var(--color-ink-3);
	}
	.price {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 144, 'wght' 400;
		font-size: 56px;
		letter-spacing: -0.03em;
		line-height: 1;
		margin-top: 4px;
	}
	.price .c {
		font-size: 0.55em;
		color: var(--color-ink-2);
		vertical-align: 0.42em;
		margin-left: 1px;
	}
	.spark { margin: 16px 0 6px; }
	.foot {
		font-family: var(--font-mono);
		font-size: 9.5px;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--color-ink-3);
	}
	.error-card {
		margin-top: 28px;
		padding: 24px;
		background: var(--color-paper-receipt);
		max-width: 400px;
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.error-card__sym {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 60, 'wght' 600;
		font-size: 22px;
	}
</style>
