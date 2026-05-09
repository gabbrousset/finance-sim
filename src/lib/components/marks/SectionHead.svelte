<script lang="ts">
  let { eyebrow, title, meta }: {
    eyebrow?: string;
    title: string;
    meta?: string;
  } = $props();
</script>

<header class="section-head">
  {#if eyebrow}<span class="eyebrow">{eyebrow}</span>{/if}
  <h1>{title}</h1>
  {#if meta}<span class="meta">{meta}</span>{/if}
</header>

<style>
  .section-head {
    display: flex;
    align-items: baseline;
    gap: 12px;
    border-bottom: 1px solid var(--color-rule);
    padding-bottom: 10px;
    margin: 32px 0 24px;
  }
  .eyebrow {
    font-family: var(--font-mono);
    font-size: 9px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    background: var(--color-stamp);
    color: var(--color-paper);
    padding: 3px 8px;
  }
  h1 {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 96, 'wght' 500;
    font-size: clamp(26px, 3.6vw, 36px);
    letter-spacing: -0.02em;
    margin: 0;
    line-height: 1;
    color: var(--color-ink);
  }
  .meta {
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--color-ink-3);
  }
</style>
