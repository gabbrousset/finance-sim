<script lang="ts">
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import { formatUsd } from '$lib/shared/money';
	import { toIsoDate } from '$lib/shared/dates';

	let { data } = $props();

	let rows = $derived(
		data.rows.map((r) => {
			const isBuy = r.shares > 0;
			return {
				date: toIsoDate(r.executedAt),
				type: isBuy ? 'buy' : 'sell',
				symbol: r.symbol,
				shares: Math.abs(r.shares).toString(),
				price: formatUsd(r.priceCents),
				amount: formatUsd(Math.abs(r.shares * r.priceCents)),
				cashAfter: formatUsd(r.runningCash)
			};
		})
	);
</script>

<h1 class="text-2xl font-semibold">history</h1>

{#if data.rows.length === 0}
	<p class="mt-6 text-zinc-500">no trades yet — <a href="/trade" class="underline">trade</a></p>
{:else}
	<div class="mt-6">
		<DataTable
			columns={[
				{ key: 'date', label: 'date' },
				{ key: 'type', label: 'type' },
				{ key: 'symbol', label: 'symbol' },
				{ key: 'shares', label: 'shares', tabular: true },
				{ key: 'price', label: 'price', tabular: true },
				{ key: 'amount', label: 'amount', tabular: true },
				{ key: 'cashAfter', label: 'cash after', tabular: true }
			]}
			{rows}
		/>
	</div>
{/if}
