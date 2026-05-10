<script lang="ts">
	import { ArrowRight } from 'lucide-svelte';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
</script>

<div class="land">
	<header class="top">
		<span class="brand">Curb <span class="amp">&amp;</span> Co.</span>
		<div class="row">
			<ThemeToggle />
			<a href="/signin" class="signin">Sign in</a>
		</div>
	</header>

	<main class="hero">
		<div class="eyebrow">Established MMXXI</div>
		<h1>An exchange for paper fortunes.</h1>
		<p class="deck">For students of the tape.</p>
		<div class="cta-row">
			<a href="/signup" class="cta cta--primary">
				Open an account <ArrowRight class="ico" />
			</a>
			<a href="/signin" class="cta cta--quiet">Already a member</a>
		</div>
	</main>

	<footer class="foot">
		Set in <span class="font-display">Fraunces</span>, <span class="font-body">Newsreader</span> <span class="amp">&amp;</span> <span class="font-mono">JetBrains Mono</span> · est. MMXXI
	</footer>
</div>

<style>
	.land {
		min-height: 100vh;
		display: flex;
		flex-direction: column;
		padding: 24px clamp(20px, 4vw, 56px);
	}
	.top {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}
	.brand {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 60, 'SOFT' 30, 'wght' 600;
		font-size: 18px;
		letter-spacing: -0.02em;
	}
	.amp { color: var(--color-stamp); }
	.row { display: flex; align-items: center; gap: 12px; }
	.signin {
		font-family: var(--font-mono);
		font-size: 11px;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-2);
		text-decoration: none;
	}
	.signin:hover { color: var(--color-ink); }

	.hero {
		flex: 1;
		max-width: 720px;
		margin: 0 auto;
		padding: 96px 0;
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	.eyebrow {
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.22em;
		text-transform: uppercase;
		color: var(--color-ink-3);
	}
	h1 {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 144, 'SOFT' 30, 'wght' 500;
		font-size: clamp(48px, 8vw, 88px);
		line-height: 0.95;
		letter-spacing: -0.035em;
		margin: 0;
	}
	.deck {
		font-family: var(--font-body);
		font-size: 18px;
		line-height: 1.55;
		color: var(--color-ink-2);
		max-width: 56ch;
		margin: 8px 0 12px;
	}
	.deck::first-line {
		font-variant: small-caps;
		letter-spacing: 0.04em;
		color: var(--color-ink);
	}

	.cta-row {
		display: flex;
		gap: 16px;
		align-items: center;
		flex-wrap: wrap;
		margin-top: 8px;
	}
	.cta {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		text-decoration: none;
	}
	.cta--primary {
		background: var(--color-ink);
		color: var(--color-paper-receipt);
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 600;
		letter-spacing: 0.18em;
		text-transform: uppercase;
		font-size: 13px;
		padding: 12px 22px;
	}
	.cta--primary:hover { opacity: 0.88; }
	:global(.cta .ico) { width: 14px; height: 14px; }
	.cta--quiet {
		color: var(--color-ink);
		border-bottom: 1px solid var(--color-rule);
		padding: 12px 0;
		font-style: italic;
		font-family: var(--font-body);
		font-size: 16px;
	}
	.cta--quiet:hover { color: var(--color-stamp); }

	.foot {
		margin-top: auto;
		padding-top: 24px;
		border-top: 1px solid var(--color-rule);
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--color-ink-3);
	}
</style>
