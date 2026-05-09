<script lang="ts">
	import FormBar from '$lib/components/marks/FormBar.svelte';

	type Row = {
		rank: number;
		name: string;
		caption?: string;
		totalCents: number;
		returnPct: number;
		formDeltas?: number[];
	};

	let { rows, formatUsd }: {
		rows: Row[];
		formatUsd: (cents: number) => string;
	} = $props();

	const ROMAN = ['', 'I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII', 'IX', 'X'];
	function roman(n: number): string {
		return ROMAN[n] ?? n.toString();
	}
</script>

<table class="st">
	<thead>
		<tr>
			<th></th>
			<th>Player</th>
			<th>Form</th>
			<th class="right">Total</th>
			<th class="right">Return</th>
		</tr>
	</thead>
	<tbody>
		{#each rows as r}
			<tr>
				<td><span class="rank" class:rank--gold={r.rank === 1}>{roman(r.rank)}</span></td>
				<td class="name">
					{r.name}
					{#if r.caption}<span class="cap">— {r.caption}</span>{/if}
				</td>
				<td>{#if r.formDeltas}<FormBar deltas={r.formDeltas} />{/if}</td>
				<td class="right total">{formatUsd(r.totalCents)}</td>
				<td class="right ret" class:up={r.returnPct > 0} class:dn={r.returnPct < 0}>
					{r.returnPct > 0 ? '+' : ''}{(r.returnPct * 100).toFixed(1)}%
				</td>
			</tr>
		{/each}
	</tbody>
</table>

<style>
	.st { width: 100%; border-collapse: collapse; }
	.st thead th {
		font-family: var(--font-mono);
		font-size: 10px;
		font-weight: 500;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--color-ink-3);
		text-align: left;
		padding: 0 12px 6px 0;
		border-bottom: 1.5px solid var(--color-ink);
	}
	.st thead th.right { text-align: right; padding-right: 0; padding-left: 12px; }
	.st tbody td {
		padding: 12px 12px 12px 0;
		border-bottom: 1px solid var(--color-rule-soft);
		vertical-align: middle;
	}
	.st tbody td.right { text-align: right; padding-right: 0; padding-left: 12px; }
	.rank {
		font-family: var(--font-display);
		font-style: italic;
		font-variation-settings: 'opsz' 60, 'wght' 600;
		font-size: 26px;
		color: var(--color-ink);
		line-height: 1;
	}
	.rank--gold { color: var(--color-stamp); }
	.name { font-family: var(--font-body); font-size: 15px; }
	.cap {
		display: block;
		font-size: 11px;
		color: var(--color-ink-3);
		font-style: italic;
	}
	.total {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 500;
		font-size: 16px;
		font-variant-numeric: tabular-nums;
	}
	.ret {
		font-family: var(--font-mono);
		font-size: 12px;
		font-variant-numeric: tabular-nums;
	}
	.ret.up { color: var(--color-gain); }
	.ret.dn { color: var(--color-loss); }
</style>
