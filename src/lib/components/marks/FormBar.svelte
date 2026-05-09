<script lang="ts">
  let { deltas, length = 6 }: { deltas: number[]; length?: number } = $props();

  const padded = $derived.by(() => {
    const out = [...deltas];
    while (out.length < length) out.unshift(0);
    return out.slice(-length);
  });

  function classFor(n: number): string {
    if (n > 0) return 'fb__seg fb__seg--up';
    if (n < 0) return 'fb__seg fb__seg--dn';
    return 'fb__seg fb__seg--flat';
  }
</script>

<span class="fb" aria-label="recent form">
  {#each padded as d}
    <span class={classFor(d)}></span>
  {/each}
</span>

<style>
  .fb { display: inline-flex; gap: 2px; }
  .fb__seg { width: 6px; height: 8px; display: inline-block; }
  .fb__seg--up   { background: var(--color-gain); }
  .fb__seg--dn   { background: var(--color-loss); }
  .fb__seg--flat { background: var(--color-rule-soft); }
</style>
