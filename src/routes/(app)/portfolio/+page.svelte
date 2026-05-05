<script lang="ts">
  import { formatUsd } from '$lib/shared/money';
  import EquityCurveChart from '$lib/components/charts/EquityCurve.svelte';
  import Sparkline from '$lib/components/charts/Sparkline.svelte';
  import DataTable from '$lib/components/tables/DataTable.svelte';
  import { onMount } from 'svelte';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();

  // Fetch sparkline data for each holding lazily after mount.
  let sparklines = $state<Record<string, { closes: number[]; dates: string[] }>>({});
  onMount(async () => {
    for (const h of data.holdings) {
      const res = await fetch(`/api/sparkline/${h.symbol}`);
      if (res.ok) {
        const json = await res.json();
        sparklines[h.symbol] = { closes: json.closes, dates: json.dates };
      }
    }
  });

  // Format holdings for the table.
  let rows = $derived(
    data.holdings.map((h) => ({
      symbol: h.symbol,
      shares: h.shares.toString(),
      price: formatUsd(h.priceCents),
      value: formatUsd(h.valueCents)
    }))
  );
</script>

<div class="p-6">
  <h1 class="text-2xl font-semibold">portfolio</h1>

  <div class="mt-6 grid grid-cols-2 gap-4 md:grid-cols-3">
    <div class="rounded-md border border-zinc-200 p-4 dark:border-zinc-800">
      <div class="text-xs text-zinc-500">cash</div>
      <div class="mono tabular mt-1 text-2xl">{formatUsd(data.cashCents)}</div>
    </div>
    <div class="rounded-md border border-zinc-200 p-4 dark:border-zinc-800">
      <div class="text-xs text-zinc-500">holdings value</div>
      <div class="mono tabular mt-1 text-2xl">{formatUsd(data.totalCents - data.cashCents)}</div>
    </div>
    <div class="col-span-2 rounded-md border border-zinc-200 p-4 md:col-span-1 dark:border-zinc-800">
      <div class="text-xs text-zinc-500">total</div>
      <div class="mono tabular mt-1 text-2xl">{formatUsd(data.totalCents)}</div>
    </div>
  </div>

  <div class="mt-8">
    <h2 class="text-sm font-medium text-zinc-500">last 30 days</h2>
    <div class="mt-2">
      <EquityCurveChart series={data.curve} />
    </div>
  </div>

  <div class="mt-8">
    <h2 class="text-sm font-medium text-zinc-500">holdings</h2>
    {#if data.holdings.length === 0}
      <p class="mt-4 text-zinc-500">no holdings yet — <a href="/trade" class="underline">trade</a></p>
    {:else}
      <div class="mt-2">
        <DataTable
          columns={[
            { key: 'symbol', label: 'symbol' },
            { key: 'shares', label: 'shares', tabular: true },
            { key: 'price', label: 'price', tabular: true },
            { key: 'value', label: 'value', tabular: true }
          ]}
          {rows}
        />
      </div>
      <div class="mt-4 grid grid-cols-2 gap-4 md:grid-cols-4">
        {#each data.holdings as h}
          {@const spark = sparklines[h.symbol]}
          <div class="rounded-md border border-zinc-200 p-3 dark:border-zinc-800">
            <div class="text-xs text-zinc-500">{h.symbol}</div>
            {#if spark}
              <Sparkline data={spark.closes} dates={spark.dates} />
            {:else}
              <div class="mt-1 h-5 w-20 animate-pulse rounded bg-zinc-200 dark:bg-zinc-800"></div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>
