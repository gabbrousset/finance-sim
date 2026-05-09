<script lang="ts">
	import SectionHead from '$lib/components/marks/SectionHead.svelte';
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import { formatUsd } from '$lib/shared/money';
	import { toIsoDate } from '$lib/shared/dates';

	let { data } = $props();

	let rows = $derived(
		data.rows.map((r) => {
			const isBuy = r.shares > 0;
			return {
				date: toIsoDate(r.executedAt),
				type: isBuy ? 'Buy' : 'Sell',
				symbol: r.symbol,
				shares: Math.abs(r.shares).toString(),
				price: formatUsd(r.priceCents),
				amount: formatUsd(Math.abs(r.shares * r.priceCents)),
				cashAfter: formatUsd(r.runningCash)
			};
		})
	);
</script>

<SectionHead
	eyebrow="IV — Ledger"
	title="The Ledger."
	meta={`${data.rows.length} ${data.rows.length === 1 ? 'entry' : 'entries'}`}
/>

{#if data.rows.length === 0}
	<p class="empty"><em>No trades yet —</em> <a href="/trade">trade</a>.</p>
{:else}
	<DataTable
		columns={[
			{ key: 'date', label: 'Date' },
			{ key: 'type', label: 'Type' },
			{ key: 'symbol', label: 'Symbol' },
			{ key: 'shares', label: 'Shares', tabular: true },
			{ key: 'price', label: 'Price', tabular: true },
			{ key: 'amount', label: 'Amount', tabular: true },
			{ key: 'cashAfter', label: 'Cash after', tabular: true }
		]}
		{rows}
	/>
{/if}

<style>
	.empty {
		font-family: var(--font-body);
		font-size: 15px;
		color: var(--color-ink-2);
	}
	.empty a { color: var(--color-ink); border-bottom: 1px solid var(--color-rule); }
</style>
