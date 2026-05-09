<script lang="ts">
	type Column = { key: string; label: string; tabular?: boolean; align?: 'left' | 'right' };
	type Row = Record<string, unknown>;
	let {
		columns,
		rows,
		empty = 'no data'
	}: { columns: Column[]; rows: Row[]; empty?: string } = $props();
</script>

<table class="dt">
	<thead>
		<tr>
			{#each columns as c}
				<th class:right={c.align === 'right' || c.tabular}>{c.label}</th>
			{/each}
		</tr>
	</thead>
	<tbody>
		{#if rows.length === 0}
			<tr><td class="empty" colspan={columns.length}>{empty}</td></tr>
		{:else}
			{#each rows as r}
				<tr>
					{#each columns as c}
						<td
							class:right={c.align === 'right' || c.tabular}
							class:tabular={c.tabular}
							class:cell-sym={c.key === 'symbol'}
						>
							{r[c.key] ?? ''}
						</td>
					{/each}
				</tr>
			{/each}
		{/if}
	</tbody>
</table>

<style>
	.dt {
		width: 100%;
		border-collapse: collapse;
		font-family: var(--font-body);
	}
	.dt thead th {
		font-family: var(--font-mono);
		font-size: 10px;
		font-weight: 500;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-3);
		text-align: left;
		padding: 0 12px 10px 0;
		border-bottom: 1.5px solid var(--color-ink);
	}
	.dt th.right { text-align: right; padding-right: 0; padding-left: 12px; }
	.dt tbody td {
		padding: 14px 12px 14px 0;
		border-bottom: 1px solid var(--color-rule-soft);
		font-size: 14px;
		color: var(--color-ink);
		vertical-align: middle;
	}
	.dt tbody td.right { text-align: right; padding-right: 0; padding-left: 12px; }
	.dt tbody td.tabular {
		font-family: var(--font-mono);
		font-variant-numeric: tabular-nums;
	}
	.dt tbody td.cell-sym {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 600;
		font-size: 18px;
		letter-spacing: -0.01em;
	}
	.dt tbody tr:last-child td { border-bottom: 1px solid var(--color-ink); }
	.dt tbody td.empty {
		text-align: center;
		padding: 24px 0;
		color: var(--color-ink-3);
		font-style: italic;
	}
</style>
