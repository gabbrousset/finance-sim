<script lang="ts">
	import { enhance } from '$app/forms';
	import Button from '$lib/components/Button.svelte';
	import SectionHead from '$lib/components/marks/SectionHead.svelte';
	import Stamp from '$lib/components/marks/Stamp.svelte';
	import { formatUsd } from '$lib/shared/money';
	import { toIsoDate } from '$lib/shared/dates';

	let { data, form } = $props();

	function variant(status: string): 'stamp' | 'ink' | 'muted' {
		if (status === 'finished') return 'ink';
		return 'stamp';
	}
</script>

<svelte:head>
	<title>Join: {data.competition.name} · finance-sim</title>
</svelte:head>

<SectionHead eyebrow="Invite" title="Join: {data.competition.name}" />

<div class="card">
	<div class="card__head">
		<span class="kind">{data.competition.type}</span>
		<Stamp label={data.competition.status} variant={variant(data.competition.status)} size="sm" />
	</div>

	<dl class="meta">
		<dt>Host</dt>
		<dd>{data.hostDisplayName}</dd>
		<dt>Window</dt>
		<dd class="mono">{toIsoDate(data.competition.startDate)} → {toIsoDate(data.competition.endDate)}</dd>
		<dt>Starting cash</dt>
		<dd class="mono">{formatUsd(data.competition.startingCashCents)}</dd>
	</dl>

	{#if data.canJoin}
		<form method="POST" use:enhance class="action">
			<Button type="submit" variant="primary">Join</Button>
		</form>
		{#if form?.error}<p class="err">{form.error}</p>{/if}
	{:else}
		<p class="closed"><em>This competition is no longer open for new members.</em></p>
	{/if}
</div>

<style>
	.card {
		background: var(--color-paper-receipt);
		padding: 24px;
		max-width: 460px;
		box-shadow: 0 14px 28px -22px rgba(22, 17, 10, 0.18);
	}
	.card__head {
		display: flex;
		justify-content: space-between;
		align-items: center;
		border-bottom: 1.5px solid var(--color-ink);
		padding-bottom: 8px;
		margin-bottom: 14px;
	}
	.kind {
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-2);
	}
	.meta {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: 4px 18px;
		margin: 0 0 18px;
	}
	.meta dt {
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--color-ink-3);
		align-self: baseline;
		padding-top: 3px;
	}
	.meta dd {
		font-family: var(--font-body);
		font-size: 14px;
		margin: 0;
		color: var(--color-ink);
	}
	.meta dd.mono {
		font-family: var(--font-mono);
		font-variant-numeric: tabular-nums;
		font-size: 13px;
	}
	.action { margin-top: 8px; }
	.err {
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--color-loss);
		margin: 8px 0 0;
	}
	.closed {
		font-family: var(--font-body);
		font-size: 14px;
		color: var(--color-ink-2);
		margin: 0;
	}
</style>
