<script lang="ts">
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
  import DataTable from '$lib/components/tables/DataTable.svelte';
  import { formatUsd } from '$lib/shared/money';
  import { toIsoDate } from '$lib/shared/dates';

  let { data } = $props();

  let rows = $derived(
    data.leaderboard.map((r) => ({
      rank: r.rank.toString(),
      name: r.displayName,
      total: formatUsd(r.totalCents),
      return: `${(r.returnPct * 100).toFixed(2)}%`
    }))
  );
</script>

<svelte:head>
  <title>{data.competition.name} — finance-sim</title>
</svelte:head>

<header class="flex items-center justify-between p-6">
  <a href="/" class="font-semibold">finance-sim</a>
  <ThemeToggle />
</header>

<main class="mx-auto max-w-2xl px-6 py-8">
  <h1 class="text-2xl font-semibold">{data.competition.name}</h1>
  <div class="mt-1 text-xs text-zinc-500">
    <span class="uppercase">{data.competition.type}</span> ·
    {toIsoDate(data.competition.startDate)} → {toIsoDate(data.competition.endDate)} ·
    starting {formatUsd(data.competition.startingCashCents)}
    {#if data.competition.finishedAt}
      · resolved {toIsoDate(data.competition.finishedAt)}
    {/if}
  </div>

  <section class="mt-8">
    <h2 class="text-sm font-medium text-zinc-500">final standings</h2>
    <div class="mt-2">
      <DataTable
        columns={[
          { key: 'rank', label: '#', tabular: true },
          { key: 'name', label: 'player' },
          { key: 'total', label: 'total', tabular: true },
          { key: 'return', label: 'return', tabular: true }
        ]}
        rows={rows}
      />
    </div>
  </section>

  <p class="mt-12 text-center text-xs text-zinc-500">
    public share. no account info shown.
  </p>
</main>
