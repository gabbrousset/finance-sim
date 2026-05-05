<script lang="ts">
	import { toIsoDate } from '$lib/shared/dates';
	import { formatUsd } from '$lib/shared/money';
	import Button from '$lib/components/Button.svelte';

	let { data } = $props();

	const statusColor: Record<string, string> = {
		open: 'bg-blue-100 text-blue-900 dark:bg-blue-900 dark:text-blue-100',
		running: 'bg-emerald-100 text-emerald-900 dark:bg-emerald-900 dark:text-emerald-100',
		finished: 'bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300'
	};
</script>

<div class="flex items-center justify-between">
	<h1 class="text-2xl font-semibold">competitions</h1>
	<a href="/competitions/new">
		<Button variant="primary">create new</Button>
	</a>
</div>

{#if data.comps.length === 0}
	<p class="mt-8 text-zinc-500">
		no competitions yet — <a href="/competitions/new" class="underline">create one</a> or join via invite
		link
	</p>
{:else}
	<ul class="mt-6 space-y-2">
		{#each data.comps as c}
			<a
				href="/competitions/{c.id}"
				class="block rounded-md border border-zinc-200 p-4 hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
			>
				<div class="flex items-baseline justify-between">
					<div>
						<span class="font-medium">{c.name}</span>
						<span class="ml-2 text-xs uppercase text-zinc-500">{c.type}</span>
						{#if c.isHost}<span class="ml-1 text-xs text-zinc-500">· host</span>{/if}
					</div>
					<span class="rounded px-2 py-0.5 text-xs font-medium {statusColor[c.status]}"
						>{c.status}</span
					>
				</div>
				<div class="mt-1 text-xs text-zinc-500">
					{toIsoDate(c.startDate)} → {toIsoDate(c.endDate)} · starting {formatUsd(
						c.startingCashCents
					)} · code <span class="font-mono">{c.inviteCode}</span>
				</div>
			</a>
		{/each}
	</ul>
{/if}
