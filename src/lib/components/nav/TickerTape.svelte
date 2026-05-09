<script lang="ts">
  type Tick = { symbol: string; price: string; pct: number };
  let { ticks }: { ticks: Tick[] } = $props();

  function fmt(t: Tick): { arrow: string; cls: string; pct: string } {
    if (t.pct > 0) return { arrow: '▲', cls: 'up', pct: `+${t.pct.toFixed(2)}%` };
    if (t.pct < 0) return { arrow: '▼', cls: 'dn', pct: `${t.pct.toFixed(2)}%` };
    return { arrow: '·', cls: '', pct: `${t.pct.toFixed(2)}%` };
  }
</script>

{#if ticks.length > 0}
  <div class="ticker" aria-hidden="true">
    <div class="track">
      {#each [...ticks, ...ticks] as t, i (i)}
        {@const f = fmt(t)}
        <span class="cell">
          {t.symbol} <strong class="tabular">{t.price}</strong>
          <span class={f.cls}>{f.arrow} {f.pct}</span>
        </span>
        <span class="div">·</span>
      {/each}
    </div>
  </div>
{/if}

<style>
  .ticker {
    background: var(--color-ink);
    color: var(--color-paper);
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.06em;
    padding: 7px 0;
    overflow: hidden;
    border-bottom: 1px solid var(--color-ink);
    box-shadow: 0 1px 0 var(--color-brass);
  }
  .track {
    display: inline-block;
    white-space: nowrap;
    padding-left: 100%;
    animation: ticker 80s linear infinite;
  }
  .cell { padding: 0 1.4em; opacity: 0.85; }
  .up { color: #87c19a; }
  .dn { color: #d49693; }
  .div { color: var(--color-brass); padding: 0 0.3em; }
  @keyframes ticker { from { transform: translateX(0); } to { transform: translateX(-50%); } }
  @media (prefers-reduced-motion: reduce) {
    .track { animation: none; padding-left: 0; }
  }
</style>
