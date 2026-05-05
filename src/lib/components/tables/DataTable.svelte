<script lang="ts">
	type Column = { key: string; label: string; tabular?: boolean };
	let {
		columns,
		rows,
		empty = 'no data'
	}: { columns: Column[]; rows: Record<string, unknown>[]; empty?: string } = $props();
</script>

<div class="overflow-x-auto">
	<table class="w-full text-sm">
		<thead>
			<tr class="border-b border-zinc-200 dark:border-zinc-800">
				{#each columns as col}
					<th
						class="px-3 py-2 text-left font-medium text-zinc-500 {col.tabular ? 'tabular' : ''}"
					>
						{col.label}
					</th>
				{/each}
			</tr>
		</thead>
		<tbody>
			{#if rows.length === 0}
				<tr>
					<td colspan={columns.length} class="px-3 py-6 text-center text-zinc-500">{empty}</td>
				</tr>
			{:else}
				{#each rows as row}
					<tr class="border-b border-zinc-100 dark:border-zinc-900">
						{#each columns as col}
							<td class="px-3 py-2 {col.tabular ? 'tabular' : ''}">{row[col.key]}</td>
						{/each}
					</tr>
				{/each}
			{/if}
		</tbody>
	</table>
</div>
