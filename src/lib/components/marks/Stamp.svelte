<script lang="ts">
  type Variant = 'stamp' | 'ink' | 'loss' | 'muted';
  type Size = 'sm' | 'md' | 'lg';
  let { label, sub, variant = 'stamp', size = 'md' }: {
    label: string;
    sub?: string;
    variant?: Variant;
    size?: Size;
  } = $props();
</script>

<span class="stamp stamp--{variant} stamp--{size}" role="img" aria-label={label}>
  <span class="stamp__label">{label}</span>
  {#if sub}<span class="stamp__sub">{sub}</span>{/if}
</span>

<style>
  .stamp {
    display: inline-block;
    font-family: var(--font-display);
    font-style: italic;
    font-variation-settings: 'opsz' 60, 'SOFT' 100, 'wght' 700;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    border-style: solid;
    transform: rotate(-4deg);
    opacity: 0.82;
    text-align: center;
    line-height: 1.05;
  }
  .stamp__sub {
    display: block;
    font-style: italic;
    font-variation-settings: 'opsz' 24, 'SOFT' 100, 'wght' 600;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    margin-top: 2px;
    opacity: 0.9;
  }
  .stamp--sm { font-size: 11px; padding: 2px 8px; border-width: 2px; }
  .stamp--sm .stamp__sub { font-size: 8px; }
  .stamp--md { font-size: 13px; padding: 4px 12px; border-width: 2.5px; }
  .stamp--md .stamp__sub { font-size: 8.5px; }
  .stamp--lg { font-size: 22px; padding: 6px 18px; border-width: 3.5px; letter-spacing: 0.22em; }
  .stamp--lg .stamp__sub { font-size: 9px; }

  .stamp--stamp { color: var(--color-stamp); border-color: var(--color-stamp); }
  .stamp--ink   { color: var(--color-ink);   border-color: var(--color-ink); }
  .stamp--loss  { color: var(--color-loss);  border-color: var(--color-loss); }
  .stamp--muted { color: var(--color-ink-2); border-color: var(--color-ink-2); opacity: 0.65; }
</style>
