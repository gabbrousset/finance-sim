<script lang="ts">
  type Stat = { label: string; value: string; cents?: string; delta?: string };
  let { stats }: { stats: Stat[] } = $props();
</script>

<section class="stat-block">
  {#each stats as s}
    <div class="stat">
      <div class="lbl">{s.label}</div>
      <div class="v tabular">
        {s.value}{#if s.cents}<span class="c">{s.cents}</span>{/if}
      </div>
      {#if s.delta}<div class="delta">{@html s.delta}</div>{/if}
    </div>
  {/each}
</section>

<style>
  .stat-block {
    display: grid;
    grid-template-columns: repeat(var(--cols, 3), 1fr);
    margin: 28px 0 36px;
  }
  @media (max-width: 640px) {
    .stat-block { grid-template-columns: 1fr; gap: 20px; }
    .stat { border-right: 0 !important; padding: 0 !important; }
  }
  .stat { padding: 4px 28px; border-right: 1px solid var(--color-rule); }
  .stat:first-child { padding-left: 0; }
  .stat:last-child  { padding-right: 0; border-right: 0; }
  .lbl {
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--color-ink-3);
    margin-bottom: 6px;
  }
  .v {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 96, 'wght' 400;
    font-size: clamp(24px, 3.6vw, 36px);
    letter-spacing: -0.025em;
    line-height: 1;
  }
  .v .c {
    font-size: 0.55em;
    color: var(--color-ink-2);
    vertical-align: 0.42em;
    margin-left: 1px;
    letter-spacing: 0.01em;
  }
  .delta {
    margin-top: 10px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--color-ink-3);
  }
  :global(.delta .pos) { color: var(--color-gain); }
  :global(.delta .neg) { color: var(--color-loss); }
</style>
