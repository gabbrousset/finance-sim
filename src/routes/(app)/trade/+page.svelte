<script lang="ts">
	import { enhance } from '$app/forms';
	import OrderTicket from '$lib/components/forms/OrderTicket.svelte';
	import SectionHead from '$lib/components/marks/SectionHead.svelte';
	import { formatUsd } from '$lib/shared/money';

	let { data, form } = $props();

	let mode: 'buy' | 'sell' = $state('buy');
	let symbol = $state('');
	let shares = $state('');

	$effect(() => {
		if (form?.success) {
			shares = '';
			return;
		}
		if (form && 'symbol' in form && typeof form.symbol === 'string') {
			symbol = form.symbol as string;
		}
		if (form && 'shares' in form && form.shares != null) {
			shares = String(form.shares);
		}
	});

	const filled = $derived(
		form?.success
			? {
					atTime: new Date().toLocaleTimeString('en-US', {
						hour: '2-digit',
						minute: '2-digit',
						hour12: false
					}),
					total: ''
				}
			: null
	);

	const nowLabel = new Date()
		.toLocaleString('en-US', { month: '2-digit', day: '2-digit', year: '2-digit' })
		.replace(/, /, ' · ');
</script>

<SectionHead eyebrow="II · Trade" title="Buy or sell." meta="At market" />

<form method="POST" use:enhance class="trade-form">
	<input type="hidden" name="mode" value={mode} />
	<OrderTicket
		{mode}
		onModeChange={(m) => (mode = m)}
		{symbol}
		onSymbolChange={(s) => (symbol = s)}
		{shares}
		onSharesChange={(s) => (shares = s)}
		cashCents={data.cashCents}
		{formatUsd}
		error={form?.error ?? undefined}
		{filled}
		{nowLabel}
	>
		<button type="submit" class="btn-place">Place order →</button>
	</OrderTicket>
</form>

{#if form?.success}
	<p class="success">{form.message} <a href="/portfolio">View the book →</a></p>
{/if}

{#if mode === 'sell' && data.holdings.length > 0}
	<section class="holdings">
		<div class="holdings__lbl">Your holdings</div>
		<ul>
			{#each data.holdings as h}
				<li>
					<button type="button" class="sym" onclick={() => (symbol = h.symbol)}>{h.symbol}</button>
					<span class="shares">{h.shares} shares</span>
				</li>
			{/each}
		</ul>
	</section>
{/if}

<style>
	.trade-form { display: contents; }
	.btn-place {
		display: block;
		width: 100%;
		background: var(--color-ink);
		color: var(--color-paper-receipt);
		border: 0;
		padding: 11px;
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 600;
		font-size: 13px;
		letter-spacing: 0.18em;
		text-transform: uppercase;
		cursor: pointer;
		margin-top: 14px;
	}
	.success {
		margin: 12px 0 0;
		font-family: var(--font-body);
		font-style: italic;
		color: var(--color-gain);
	}
	.success a {
		color: var(--color-ink);
		border-bottom: 1px solid var(--color-rule);
	}
	.holdings { margin-top: 32px; }
	.holdings__lbl {
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-3);
		margin-bottom: 8px;
	}
	.holdings ul { list-style: none; padding: 0; margin: 0; }
	.holdings li {
		display: flex;
		gap: 14px;
		padding: 6px 0;
		align-items: baseline;
	}
	.sym {
		background: transparent;
		border: 0;
		padding: 0;
		cursor: pointer;
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 600;
		font-size: 16px;
		color: var(--color-ink);
	}
	.sym:hover { color: var(--color-stamp); }
	.shares { font-family: var(--font-mono); font-size: 12px; color: var(--color-ink-3); }
</style>
