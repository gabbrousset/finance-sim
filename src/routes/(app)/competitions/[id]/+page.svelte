<script lang="ts">
	import { enhance } from '$app/forms';
	import { invalidateAll } from '$app/navigation';
	import OrderTicket from '$lib/components/forms/OrderTicket.svelte';
	import SectionHead from '$lib/components/marks/SectionHead.svelte';
	import StandingsTable from '$lib/components/tables/StandingsTable.svelte';
	import PullQuote from '$lib/components/marks/PullQuote.svelte';
	import Stamp from '$lib/components/marks/Stamp.svelte';
	import Button from '$lib/components/Button.svelte';
	import { formatUsd } from '$lib/shared/money';
	import { toIsoDate } from '$lib/shared/dates';

	let { data, form } = $props();

	let mode: 'buy' | 'sell' = $state('buy');
	let symbol = $state('');
	let shares = $state('');

	let polledLeaderboard: typeof data.leaderboard | null = $state(null);
	let leaderboard = $derived(polledLeaderboard ?? data.leaderboard);

	$effect(() => {
		if (data.dashboard.competition.status === 'running') {
			polledLeaderboard = null;
			const t = setInterval(async () => {
				const r = await fetch(`/api/leaderboard/${data.dashboard.competition.id}`);
				if (r.ok) {
					const j = await r.json();
					polledLeaderboard = j.rows;
				}
			}, 5000);
			return () => {
				clearInterval(t);
				polledLeaderboard = null;
			};
		}
	});

	let canTrade = $derived(
		(data.dashboard.competition.type === 'live' &&
			data.dashboard.competition.status === 'running') ||
			(data.dashboard.competition.type === 'historical' &&
				data.dashboard.competition.status === 'open')
	);

	const standings = $derived(
		leaderboard.map((r) => ({
			rank: r.rank,
			name: r.displayName,
			caption: undefined as string | undefined,
			totalCents: r.totalCents,
			returnPct: r.returnPct,
			formDeltas: undefined as number[] | undefined
		}))
	);

	const leader = $derived(standings[0]);

	const statusInfo = $derived.by(() => {
		if (data.dashboard.competition.status === 'finished') {
			return {
				label: 'Final',
				sub: leader ? `Champion: ${leader.name}` : '— sealed —',
				variant: 'ink' as const
			};
		}
		return {
			label: 'Provisional',
			sub: `— sealed ${toIsoDate(data.dashboard.competition.endDate)} —`,
			variant: 'stamp' as const
		};
	});
</script>

<SectionHead
	eyebrow="Standings"
	title={data.dashboard.competition.name}
	meta={`${data.dashboard.competition.type} · code ${data.dashboard.competition.inviteCode}`}
/>

<p class="deck">
	<em>
		{leaderboard.length}
		{leaderboard.length === 1 ? 'player' : 'players'}, starting
		{formatUsd(data.dashboard.competition.startingCashCents)} each, sealed
		{toIsoDate(data.dashboard.competition.endDate)}.
	</em>
</p>

{#if leader && leader.returnPct !== 0}
	<PullQuote badge={leader.name.charAt(0).toUpperCase()}>
		"<strong>{leader.name}</strong>
		{leader.returnPct > 0 ? 'up' : 'down'}
		<strong>{(Math.abs(leader.returnPct) * 100).toFixed(1)}%</strong>
		— <em>{leader.returnPct > 0 ? 'in good form.' : 'looking for a comeback.'}</em>"
	</PullQuote>
{/if}

<div class="standings">
	<StandingsTable rows={standings} {formatUsd} />
</div>

<div class="status-row">
	<Stamp label={statusInfo.label} sub={statusInfo.sub} variant={statusInfo.variant} size="md" />
</div>

{#if data.dashboard.isHost}
	<section class="host-controls">
		<SectionHead title="Host controls." />
		{#if data.dashboard.competition.type === 'historical' && data.dashboard.competition.status === 'open'}
			<form method="POST" action="?/resolve" use:enhance={() => () => invalidateAll()}>
				<Button type="submit" variant="primary">Resolve now</Button>
			</form>
		{/if}
		{#if data.dashboard.competition.status === 'finished'}
			<form method="POST" action="?/toggleShare" use:enhance={() => () => invalidateAll()}>
				<input
					type="hidden"
					name="value"
					value={data.dashboard.competition.shareResults ? '0' : '1'}
				/>
				<Button type="submit" variant="quiet">
					{data.dashboard.competition.shareResults
						? 'Unshare results'
						: 'Share results publicly'}
				</Button>
			</form>
		{/if}
	</section>
{/if}

<section class="my">
	<SectionHead title="My positions." meta={`Cash ${formatUsd(data.dashboard.myCashCents)}`} />
	{#if data.dashboard.myHoldings.length > 0}
		<ul class="my-list">
			{#each data.dashboard.myHoldings as h}
				<li><span class="sym">{h.symbol}</span><span class="sh">{h.shares} shares</span></li>
			{/each}
		</ul>
	{:else}
		<p class="empty"><em>No positions of record.</em></p>
	{/if}
</section>

{#if canTrade}
	<section class="trade">
		<SectionHead title="Place an order." />
		<form method="POST" action="?/trade" use:enhance={() => () => invalidateAll()}>
			<input type="hidden" name="mode" value={mode} />
			<OrderTicket
				{mode}
				onModeChange={(m) => (mode = m)}
				{symbol}
				onSymbolChange={(s) => (symbol = s)}
				{shares}
				onSharesChange={(s) => (shares = s)}
				cashCents={data.dashboard.myCashCents}
				{formatUsd}
				error={form?.tradeError ?? undefined}
			>
				<button type="submit" class="btn-place">Place order →</button>
			</OrderTicket>
		</form>
		{#if form?.tradeOk}<p class="ok"><em>{form.tradeOk}</em></p>{/if}
	</section>
{/if}

<style>
	.deck {
		font-family: var(--font-body);
		font-style: italic;
		font-size: 14px;
		color: var(--color-ink-2);
		margin: 0 0 18px;
		max-width: 640px;
	}
	.standings { margin-top: 18px; }
	.status-row { margin-top: 22px; text-align: right; }
	.host-controls, .my, .trade { margin-top: 8px; }
	.my-list { list-style: none; padding: 0; margin: 8px 0 0; }
	.my-list li {
		display: flex;
		gap: 14px;
		padding: 6px 0;
		align-items: baseline;
		border-bottom: 1px solid var(--color-rule-soft);
	}
	.sym {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 600;
		font-size: 16px;
	}
	.sh { font-family: var(--font-mono); font-size: 12px; color: var(--color-ink-3); }
	.empty {
		font-family: var(--font-body);
		font-style: italic;
		color: var(--color-ink-2);
	}
	.ok { font-family: var(--font-body); color: var(--color-gain); }
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
</style>
