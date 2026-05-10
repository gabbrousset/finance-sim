<script lang="ts">
	import { toIsoDate } from '$lib/shared/dates';
	import { formatUsd } from '$lib/shared/money';
	import Button from '$lib/components/Button.svelte';
	import SectionHead from '$lib/components/marks/SectionHead.svelte';
	import Stamp from '$lib/components/marks/Stamp.svelte';

	let { data } = $props();

	function stampVariant(status: string): 'stamp' | 'ink' | 'muted' {
		if (status === 'finished') return 'ink';
		return 'stamp';
	}
</script>

<div class="head">
	<SectionHead eyebrow="V — Competitions" title="Competitions." meta="Hosting + joined" />
	<a href="/competitions/new" class="cta">
		<Button variant="primary">Create new</Button>
	</a>
</div>

{#if data.comps.length === 0}
	<p class="empty">
		None of record. <a href="/competitions/new">Open one →</a> or join by invitation.
	</p>
{:else}
	<ul class="list">
		{#each data.comps as c}
			<li>
				<a href="/competitions/{c.id}">
					<div class="row">
						<div>
							<div class="name">{c.name}</div>
							<div class="meta">
								<span class="type">{c.type}</span>
								{#if c.isHost}<span class="host">· host</span>{/if}
								· {toIsoDate(c.startDate)} → {toIsoDate(c.endDate)}
								· starting {formatUsd(c.startingCashCents)}
								· code <span class="code">{c.inviteCode}</span>
							</div>
						</div>
						<Stamp label={c.status} variant={stampVariant(c.status)} size="sm" />
					</div>
				</a>
			</li>
		{/each}
	</ul>
{/if}

<style>
	.head {
		display: flex;
		align-items: flex-end;
		justify-content: space-between;
		gap: 16px;
	}
	.head .cta { padding-bottom: 10px; }
	.empty {
		font-family: var(--font-body);
		font-size: 15px;
		color: var(--color-ink-2);
	}
	.empty a { color: var(--color-ink); border-bottom: 1px solid var(--color-rule); }
	.list { list-style: none; padding: 0; margin: 0; }
	.list li { border-bottom: 1px solid var(--color-rule-soft); }
	.list a {
		display: block;
		text-decoration: none;
		color: var(--color-ink);
		padding: 16px 0;
	}
	.list a:hover { background: var(--color-paper-2); }
	.row {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
	}
	.name {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 600;
		font-size: 18px;
		letter-spacing: -0.01em;
	}
	.meta {
		margin-top: 3px;
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--color-ink-3);
		letter-spacing: 0.04em;
	}
	.type {
		text-transform: uppercase;
		letter-spacing: 0.12em;
	}
	.host { color: var(--color-ink-2); }
	.code { color: var(--color-ink-2); }
</style>
