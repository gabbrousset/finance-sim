<script lang="ts">
  let { editionNo, date, status }: {
    editionNo: number;
    date: Date;
    status?: string;
  } = $props();

  const weekday = $derived(date.toLocaleDateString('en-US', { weekday: 'long' }));
  const dateStr = $derived(date.toLocaleDateString('en-US', {
    month: 'long', day: 'numeric', year: 'numeric'
  }));
</script>

<header class="mh">
  <div class="mh__side">
    Volume III · No. {editionNo}<br/>
    Established MMXXI
  </div>
  <div class="mh__center">
    <div class="mh__title">Curb <span class="amp">&amp;</span> Co.</div>
    <div class="mh__sub">A daily ledger of paper positions, plainly kept.</div>
  </div>
  <div class="mh__side mh__side--r">
    {weekday}<br/>
    {dateStr}<br/>
    {status ?? 'Closed · 16:00 ET'}
  </div>
</header>

<style>
  .mh {
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    align-items: end;
    gap: 24px;
    border-bottom: 3px double var(--color-ink);
    padding-bottom: 16px;
    margin-bottom: 8px;
  }
  .mh__side {
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--color-ink-3);
    line-height: 1.6;
  }
  .mh__side--r { text-align: right; }
  .mh__title {
    font-family: var(--font-display);
    font-variation-settings: 'opsz' 144, 'SOFT' 30, 'wght' 500;
    font-size: clamp(36px, 6vw, 56px);
    line-height: 0.92;
    letter-spacing: -0.025em;
    text-align: center;
    color: var(--color-ink);
    white-space: nowrap;
  }
  .amp {
    color: var(--color-stamp);
    font-variation-settings: 'opsz' 144, 'SOFT' 100, 'wght' 400;
  }
  .mh__sub {
    margin-top: 6px;
    text-align: center;
    font-family: var(--font-body);
    font-style: italic;
    font-size: 13px;
    color: var(--color-ink-2);
  }
  @media (max-width: 720px) {
    .mh { grid-template-columns: 1fr; gap: 8px; }
    .mh__side { display: none; }
  }
</style>
