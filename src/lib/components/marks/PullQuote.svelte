<script lang="ts">
  let { badge, children }: {
    badge?: string;
    children: import('svelte').Snippet;
  } = $props();
</script>

<aside class="pq">
  {#if badge}<span class="pq__badge">{badge}</span>{/if}
  <span class="pq__line">{@render children()}</span>
</aside>

<style>
  .pq {
    background: var(--color-paper-2);
    padding: 12px 14px;
    border-left: 3px solid var(--color-stamp);
    display: flex; align-items: center; gap: 14px;
    margin: 0 0 18px;
  }
  .pq__badge {
    width: 44px; height: 44px;
    border-radius: 50%;
    background: var(--color-ink);
    color: var(--color-paper);
    display: grid; place-items: center;
    font-family: var(--font-display);
    font-style: italic;
    font-variation-settings: 'opsz' 24, 'wght' 600;
    font-size: 22px;
    flex-shrink: 0;
  }
  .pq__line {
    font-family: var(--font-display);
    font-style: italic;
    font-variation-settings: 'opsz' 60, 'wght' 400;
    font-size: 17px;
    line-height: 1.3;
    color: var(--color-ink);
    letter-spacing: -0.005em;
  }
  :global(.pq__line strong) {
    font-style: normal;
    color: var(--color-stamp);
    font-variation-settings: 'opsz' 60, 'wght' 600;
  }
</style>
