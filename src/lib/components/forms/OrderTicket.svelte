<script lang="ts">
	import Stamp from '$lib/components/marks/Stamp.svelte';

	type Props = {
		mode: 'buy' | 'sell';
		onModeChange: (m: 'buy' | 'sell') => void;
		symbol: string;
		onSymbolChange: (s: string) => void;
		shares: string;
		onSharesChange: (s: string) => void;
		cashCents: number;
		formatUsd: (c: number) => string;
		lastPriceCents?: number;
		error?: string;
		filled?: { atTime: string; total: string } | null;
		children?: import('svelte').Snippet;
		no?: number;
		nowLabel?: string;
	};

	let {
		mode,
		onModeChange,
		symbol,
		onSymbolChange,
		shares,
		onSharesChange,
		cashCents,
		formatUsd,
		lastPriceCents,
		error,
		filled,
		children,
		no = 1,
		nowLabel
	}: Props = $props();

	const totalCost = $derived.by(() => {
		const n = parseInt(shares || '0', 10);
		if (!n || !lastPriceCents) return null;
		return n * lastPriceCents;
	});
</script>

<div class="ticket">
	<span class="ticket__dup">— duplicate · file copy —</span>

	<div class="ticket__head">
		<h3>Order Ticket</h3>
		<div class="ticket__meta">
			No. {no.toString().padStart(4, '0')}<br/>
			{nowLabel ?? ''}
		</div>
	</div>

	<div class="ticket__balance">
		<span class="bal-k">Balance</span>
		<span class="bal-v">{formatUsd(cashCents)}</span>
	</div>

	<div class="ticket__toggle">
		<button type="button" class:on={mode === 'buy'} onclick={() => onModeChange('buy')}>Buy</button>
		<button type="button" class:on={mode === 'sell'} onclick={() => onModeChange('sell')}>Sell</button>
	</div>

	<div class="ticket__field">
		<div class="lbl">Symbol</div>
		<input
			class="input"
			name="symbol"
			autocomplete="off"
			autocapitalize="characters"
			placeholder="e.g. AAPL"
			value={symbol}
			oninput={(e) => onSymbolChange((e.currentTarget as HTMLInputElement).value)}
			required
		/>
	</div>

	<div class="ticket__field">
		<div class="lbl">Shares</div>
		<input
			class="input"
			name="shares"
			type="number"
			inputmode="numeric"
			min="1"
			placeholder="e.g. 5"
			value={shares}
			oninput={(e) => onSharesChange((e.currentTarget as HTMLInputElement).value)}
			required
		/>
	</div>

	{#if shares && parseInt(shares, 10) > 0}
		<div class="ticket__totals">
			{#if lastPriceCents}
				<div class="row"><span class="k">Last price</span><span class="v">{formatUsd(lastPriceCents)}</span></div>
			{/if}
			<div class="row"><span class="k">Commission</span><span class="v">$0.00</span></div>
			{#if totalCost != null}
				<div class="row big">
					<span class="k">Total cost</span>
					<span class="v">{formatUsd(totalCost)}</span>
				</div>
			{/if}
		</div>
	{/if}

	{#if error}<p class="ticket__error">{error}</p>{/if}

	{@render children?.()}

	{#if filled}
		<div class="ticket__stamp">
			<Stamp label="Filled" sub="— booked at {filled.atTime} —" size="lg" />
		</div>
	{/if}
</div>

<style>
	.ticket {
		position: relative;
		background: var(--color-paper-receipt);
		box-shadow: 0 1px 0 rgba(22, 17, 10, 0.04), 0 14px 28px -20px rgba(22, 17, 10, 0.22);
		padding: 22px 22px 18px;
		margin: 4px 0 14px;
		max-width: 460px;
	}
	.ticket::before, .ticket::after {
		content: "";
		position: absolute;
		left: 0;
		right: 0;
		height: 8px;
		background: radial-gradient(circle at 4px 8px, var(--color-paper) 3.5px, transparent 4px) 0 0/8px 8px repeat-x;
	}
	.ticket::before { top: -7px; }
	.ticket::after { bottom: -7px; transform: scaleY(-1); }

	.ticket__dup {
		position: absolute;
		top: 14px;
		right: 18px;
		font-family: var(--font-display);
		font-style: italic;
		font-variation-settings: 'opsz' 24, 'wght' 600, 'SOFT' 100;
		font-size: 10px;
		letter-spacing: 0.18em;
		text-transform: uppercase;
		color: var(--color-stamp);
		opacity: 0.55;
		transform: rotate(-2deg);
		pointer-events: none;
	}

	.ticket__head {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		border-bottom: 1.5px solid var(--color-ink);
		padding-bottom: 8px;
		margin-bottom: 12px;
	}
	.ticket__head h3 {
		margin: 0;
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 60, 'wght' 600;
		font-size: 18px;
		letter-spacing: -0.01em;
	}
	.ticket__meta {
		font-family: var(--font-mono);
		font-size: 9.5px;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--color-ink-3);
		text-align: right;
		line-height: 1.5;
	}

	.ticket__balance {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		padding: 4px 0 12px;
		margin-bottom: 14px;
		border-bottom: 1px dashed var(--color-rule);
	}
	.bal-k {
		font-family: var(--font-mono);
		font-size: 9px;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-3);
	}
	.bal-v {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 500;
		font-size: 18px;
		font-variant-numeric: tabular-nums;
		letter-spacing: -0.01em;
		color: var(--color-ink);
	}

	.ticket__toggle {
		display: inline-flex;
		border: 1.5px solid var(--color-ink);
		margin-bottom: 14px;
	}
	.ticket__toggle button {
		padding: 6px 18px;
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		background: transparent;
		color: var(--color-ink);
		border: 0;
		cursor: pointer;
	}
	.ticket__toggle button.on {
		background: var(--color-ink);
		color: var(--color-paper-receipt);
	}

	.ticket__field { margin-bottom: 12px; }
	.ticket__field .lbl {
		font-family: var(--font-mono);
		font-size: 9px;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-3);
		margin-bottom: 4px;
	}
	.ticket__field .input {
		width: 100%;
		background: transparent;
		border: 0;
		border-bottom: 1.5px solid var(--color-ink);
		outline: none;
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 500;
		font-size: 22px;
		letter-spacing: -0.015em;
		color: var(--color-ink);
		padding: 2px 0 4px;
	}
	.ticket__field .input:focus { border-bottom-width: 2px; }
	.ticket__field .input::placeholder {
		color: var(--color-ink-3);
		font-style: italic;
		font-variation-settings: 'opsz' 24, 'wght' 400;
		opacity: 0.65;
	}

	.ticket__totals {
		margin-top: 12px;
		padding-top: 10px;
		border-top: 1px dashed var(--color-rule);
		font-family: var(--font-mono);
		font-size: 11px;
		line-height: 1.6;
	}
	.ticket__totals .row { display: flex; justify-content: space-between; }
	.ticket__totals .row .k {
		color: var(--color-ink-3);
		text-transform: uppercase;
		letter-spacing: 0.14em;
		font-size: 9px;
		padding-top: 3px;
	}
	.ticket__totals .row.big {
		margin-top: 8px;
		padding-top: 8px;
		border-top: 1.5px solid var(--color-ink);
		font-size: 13px;
	}
	.ticket__totals .row.big .v {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 600;
		font-size: 18px;
		letter-spacing: -0.01em;
	}

	.ticket__error {
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--color-loss);
		margin: 8px 0 0;
	}

	.ticket__stamp {
		margin-top: 12px;
		text-align: right;
	}
</style>
