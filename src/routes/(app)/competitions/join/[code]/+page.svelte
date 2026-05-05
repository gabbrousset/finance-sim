<script lang="ts">
	import { enhance } from '$app/forms';
	import Button from '$lib/components/Button.svelte';
	import { formatUsd } from '$lib/shared/money';
	import { toIsoDate } from '$lib/shared/dates';

	let { data, form } = $props();

	const statusColor: Record<string, string> = {
		open: 'bg-blue-100 text-blue-900 dark:bg-blue-900 dark:text-blue-100',
		running: 'bg-emerald-100 text-emerald-900 dark:bg-emerald-900 dark:text-emerald-100',
		finished: 'bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300'
	};
</script>

<h1 class="text-2xl font-semibold">join competition</h1>

<div class="mt-6 max-w-md rounded-md border border-zinc-200 p-6 dark:border-zinc-800">
	<div class="flex items-baseline justify-between">
		<span class="text-lg font-medium">{data.competition.name}</span>
		<span class="rounded px-2 py-0.5 text-xs font-medium {statusColor[data.competition.status]}"
			>{data.competition.status}</span
		>
	</div>
	<dl class="mt-4 grid grid-cols-2 gap-2 text-sm">
		<dt class="text-zinc-500">type</dt>
		<dd class="uppercase">{data.competition.type}</dd>
		<dt class="text-zinc-500">host</dt>
		<dd>{data.hostDisplayName}</dd>
		<dt class="text-zinc-500">window</dt>
		<dd class="mono tabular"
			>{toIsoDate(data.competition.startDate)} → {toIsoDate(data.competition.endDate)}</dd
		>
		<dt class="text-zinc-500">starting cash</dt>
		<dd class="mono tabular">{formatUsd(data.competition.startingCashCents)}</dd>
	</dl>

	{#if data.canJoin}
		<form method="POST" use:enhance class="mt-6">
			<Button type="submit" variant="primary">join</Button>
		</form>
		{#if form?.error}
			<p class="mt-2 text-sm text-red-600">{form.error}</p>
		{/if}
	{:else}
		<p class="mt-6 text-sm text-zinc-500">
			this competition is no longer open for new members.
		</p>
	{/if}
</div>
