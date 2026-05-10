<script lang="ts">
  import { formatUsd } from '$lib/shared/money';
  import EquityCurveChart from '$lib/components/charts/EquityCurve.svelte';
  import Sparkline from '$lib/components/charts/Sparkline.svelte';
  import Masthead from '$lib/components/marks/Masthead.svelte';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import StatBlock from '$lib/components/marks/StatBlock.svelte';
  import { onMount } from 'svelte';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();

  let sparklines = $state<Record<string, { closes: number[]; dates: string[] }>>({});
  onMount(async () => {
    for (const h of data.holdings) {
      const res = await fetch(`/api/sparkline/${h.symbol}`);
      if (res.ok) {
        const j = await res.json();
        sparklines[h.symbol] = { closes: j.closes, dates: j.dates };
      }
    }
  });

  const stats = $derived([
    { label: 'Cash on hand', value: formatUsd(data.cashCents) },
    { label: 'Holdings, mkt.', value: formatUsd(data.totalCents - data.cashCents) },
    { label: 'Account total', value: formatUsd(data.totalCents) }
  ]);

  const editionNo = $derived(((data as unknown) as { editionNo?: number }).editionNo ?? 1);
</script>

<Masthead {editionNo} date={new Date()} />

<SectionHead eyebrow="I · Portfolio" title="The Portfolio." meta="As of close" />

<StatBlock {stats} />

<EquityCurveChart series={data.curve} />

<SectionHead
  title="Holdings."
  meta={`${data.holdings.length} ${data.holdings.length === 1 ? 'position' : 'positions'}`}
/>

{#if data.holdings.length === 0}
  <p class="empty">The book is empty. <a href="/trade">Trade →</a></p>
{:else}
  <table class="hold">
    <thead>
      <tr>
        <th>Symbol</th>
        <th class="spark-col">Last 30d</th>
        <th class="num">Shares</th>
        <th class="num">Last</th>
        <th class="num">Position</th>
      </tr>
    </thead>
    <tbody>
      {#each data.holdings as h}
        {@const sp = sparklines[h.symbol]}
        <tr>
          <td class="sym">{h.symbol}</td>
          <td class="spark-col">
            {#if sp}
              <Sparkline data={sp.closes} dates={sp.dates} width={120} height={28} />
            {/if}
          </td>
          <td class="num">{h.shares}</td>
          <td class="num">{formatUsd(h.priceCents)}</td>
          <td class="num val">{formatUsd(h.valueCents)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

<style>
  .empty {
    font-family: var(--font-body);
    font-size: 15px;
    color: var(--color-ink-2);
  }
  .empty a { color: var(--color-ink); border-bottom: 1px solid var(--color-rule); }

  .hold {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--font-body);
  }
  .hold thead th {
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
  .hold thead th.num { text-align: right; padding-right: 0; padding-left: 12px; }
  .hold thead th.spark-col { width: 140px; }
  .hold tbody td {
    padding: 14px 12px 14px 0;
    border-bottom: 1px solid var(--color-rule-soft);
    font-size: 14px;
    color: var(--color-ink);
    vertical-align: middle;
  }
  .hold tbody tr:last-child td { border-bottom: 1px solid var(--color-ink); }
  .hold td.num {
    text-align: right;
    padding-right: 0;
    padding-left: 12px;
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
  }
  .hold td.sym {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 18px;
    letter-spacing: -0.01em;
  }
  .hold td.val {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 500;
    font-size: 16px;
    letter-spacing: -0.005em;
  }
  .hold td.spark-col { padding-right: 12px; }
</style>
