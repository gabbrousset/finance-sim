<script lang="ts">
  import { formatUsd } from '$lib/shared/money';
  import EquityCurveChart from '$lib/components/charts/EquityCurve.svelte';
  import Sparkline from '$lib/components/charts/Sparkline.svelte';
  import Masthead from '$lib/components/marks/Masthead.svelte';
  import SectionHead from '$lib/components/marks/SectionHead.svelte';
  import StatBlock from '$lib/components/marks/StatBlock.svelte';
  import DataTable from '$lib/components/tables/DataTable.svelte';
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

  let rows = $derived(
    data.holdings.map((h) => ({
      symbol: h.symbol,
      shares: h.shares.toString(),
      price: formatUsd(h.priceCents),
      value: formatUsd(h.valueCents)
    }))
  );

  const stats = $derived([
    { label: 'Cash on hand', value: formatUsd(data.cashCents) },
    { label: 'Holdings, mkt.', value: formatUsd(data.totalCents - data.cashCents) },
    { label: 'Account total', value: formatUsd(data.totalCents) }
  ]);

  const editionNo = $derived(((data as unknown) as { editionNo?: number }).editionNo ?? 1);
</script>

<Masthead {editionNo} date={new Date()} />

<SectionHead eyebrow="I — Portfolio" title="The Portfolio." meta="As of close" />

<StatBlock {stats} />

<EquityCurveChart series={data.curve} />

<SectionHead title="Holdings." meta={`${data.holdings.length} ${data.holdings.length === 1 ? 'position' : 'positions'}`} />

{#if data.holdings.length === 0}
  <p class="empty"><em>No holdings yet —</em> <a href="/trade">trade</a>.</p>
{:else}
  <DataTable
    columns={[
      { key: 'symbol', label: 'Symbol' },
      { key: 'shares', label: 'Shares', tabular: true },
      { key: 'price',  label: 'Last',   tabular: true },
      { key: 'value',  label: 'Position', tabular: true }
    ]}
    {rows}
  />

  <div class="sparks">
    {#each data.holdings as h}
      {@const sp = sparklines[h.symbol]}
      <div class="sparks__item">
        <span class="sym">{h.symbol}</span>
        {#if sp}
          <Sparkline data={sp.closes} dates={sp.dates} width={140} height={32} />
        {/if}
      </div>
    {/each}
  </div>
{/if}

<style>
  .empty {
    font-family: var(--font-body);
    font-size: 15px;
    color: var(--color-ink-2);
  }
  .empty a { color: var(--color-ink); border-bottom: 1px solid var(--color-rule); }
  .sparks {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 14px;
    margin-top: 24px;
  }
  .sparks__item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-top: 1px solid var(--color-rule-soft);
    padding-top: 8px;
  }
  .sym {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 16px;
  }
</style>
