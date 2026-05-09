<script lang="ts">
	import { enhance } from '$app/forms';
	import { invalidateAll } from '$app/navigation';
	import TextField from '$lib/components/forms/TextField.svelte';
	import Button from '$lib/components/Button.svelte';
	import FormError from '$lib/components/forms/FormError.svelte';
	import DataTable from '$lib/components/tables/DataTable.svelte';
	import { formatUsd } from '$lib/shared/money';
	import { toIsoDate } from '$lib/shared/dates';

	let { data, form } = $props();

	let mode: 'buy' | 'sell' = $state('buy');
	let symbol = $state('');
	let shares = $state('');

	// Polling: polled rows override server rows while polling is active.
	let polledLeaderboard: typeof data.leaderboard | null = $state(null);
	let leaderboard = $derived(polledLeaderboard ?? data.leaderboard);

	$effect(() => {
		if (data.dashboard.competition.status === 'running') {
			polledLeaderboard = null; // reset when data refreshes
			const pollInterval = setInterval(async () => {
				const r = await fetch(`/api/leaderboard/${data.dashboard.competition.id}`);
				if (r.ok) {
					const j = await r.json();
					polledLeaderboard = j.rows;
				}
			}, 5000);
			return () => {
				clearInterval(pollInterval);
				polledLeaderboard = null;
			};
		}
	});

	let canTrade = $derived(
		(data.dashboard.competition.type === 'live' && data.dashboard.competition.status === 'running') ||
			(data.dashboard.competition.type === 'historical' &&
				data.dashboard.competition.status === 'open')
	);

	const statusColor: Record<string, string> = {
		open: 'bg-blue-100 text-blue-900 dark:bg-blue-900 dark:text-blue-100',
		running: 'bg-emerald-100 text-emerald-900 dark:bg-emerald-900 dark:text-emerald-100',
		finished: 'bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300'
	};

	let leaderboardRows = $derived(
		leaderboard.map((r) => ({
			rank: r.rank.toString(),
			name: r.displayName,
			total: formatUsd(r.totalCents),
			return: `${(r.returnPct * 100).toFixed(2)}%`
		}))
	);

	let holdingsRows = $derived(
		data.dashboard.myHoldings.map((h) => ({
			symbol: h.symbol,
			shares: h.shares.toString()
		}))
	);
</script>

<header class="flex items-baseline justify-between">
	<div>
		<h1 class="text-2xl font-semibold">{data.dashboard.competition.name}</h1>
		<div class="mt-1 text-xs text-zinc-500">
			<span class="uppercase">{data.dashboard.competition.type}</span> ·
			{toIsoDate(data.dashboard.competition.startDate)} → {toIsoDate(
				data.dashboard.competition.endDate
			)} · starting {formatUsd(data.dashboard.competition.startingCashCents)} · code
			<span class="font-mono">{data.dashboard.competition.inviteCode}</span>
		</div>
	</div>
	<span
		class="rounded px-2 py-0.5 text-xs font-medium {statusColor[
			data.dashboard.competition.status
		]}"
	>
		{data.dashboard.competition.status}
	</span>
</header>

<!-- leaderboard -->
<section class="mt-8">
	<h2 class="text-sm font-medium text-zinc-500">leaderboard</h2>
	<div class="mt-2">
		<DataTable
			columns={[
				{ key: 'rank', label: '#', tabular: true },
				{ key: 'name', label: 'player' },
				{ key: 'total', label: 'total', tabular: true },
				{ key: 'return', label: 'return', tabular: true }
			]}
			rows={leaderboardRows}
		/>
	</div>
</section>

<!-- host controls -->
{#if data.dashboard.isHost}
	<section class="mt-8">
		<h2 class="text-sm font-medium text-zinc-500">host controls</h2>
		{#if data.dashboard.competition.type === 'historical' && data.dashboard.competition.status === 'open'}
			<form
				method="POST"
				action="?/resolve"
				use:enhance={() => () => invalidateAll()}
				class="mt-2"
			>
				<Button type="submit" variant="primary">resolve now</Button>
			</form>
		{/if}
		{#if data.dashboard.competition.status === 'finished'}
			<form
				method="POST"
				action="?/toggleShare"
				use:enhance={() => () => invalidateAll()}
				class="mt-2"
			>
				<input
					type="hidden"
					name="value"
					value={data.dashboard.competition.shareResults ? '0' : '1'}
				/>
				<Button type="submit" variant="quiet">
					{data.dashboard.competition.shareResults ? 'unshare results' : 'share results publicly'}
				</Button>
			</form>
		{/if}
	</section>
{/if}

<!-- my portfolio -->
<section class="mt-8">
	<h2 class="text-sm font-medium text-zinc-500">my portfolio</h2>
	<div class="mt-2 text-sm">
		cash: <span class="mono tabular">{formatUsd(data.dashboard.myCashCents)}</span>
	</div>
	{#if data.dashboard.myHoldings.length > 0}
		<div class="mt-2">
			<DataTable
				columns={[
					{ key: 'symbol', label: 'symbol' },
					{ key: 'shares', label: 'shares', tabular: true }
				]}
				rows={holdingsRows}
			/>
		</div>
	{/if}
</section>

<!-- trade form -->
{#if canTrade}
	<section class="mt-8">
		<h2 class="text-sm font-medium text-zinc-500">trade</h2>
		<div class="mt-2 inline-flex rounded-md border border-zinc-200 dark:border-zinc-800">
			<button
				type="button"
				onclick={() => (mode = 'buy')}
				class="px-4 py-2 text-sm {mode === 'buy'
					? 'bg-zinc-900 text-white dark:bg-white dark:text-zinc-900'
					: ''}"
			>buy</button>
			<button
				type="button"
				onclick={() => (mode = 'sell')}
				class="px-4 py-2 text-sm {mode === 'sell'
					? 'bg-zinc-900 text-white dark:bg-white dark:text-zinc-900'
					: ''}"
			>sell</button>
		</div>
		<form
			method="POST"
			action="?/trade"
			use:enhance={() => () => invalidateAll()}
			class="mt-4 flex max-w-sm flex-col gap-3"
		>
			<input type="hidden" name="mode" value={mode} />
			<TextField name="symbol" label="symbol" bind:value={symbol} required />
			<TextField name="shares" label="shares" type="number" bind:value={shares} required />
			<FormError message={form?.tradeError ?? ''} />
			{#if form?.tradeOk}
				<p class="text-sm text-emerald-700 dark:text-emerald-400">{form.tradeOk}</p>
			{/if}
			<Button type="submit" variant="primary">{mode}</Button>
		</form>
	</section>
{/if}
