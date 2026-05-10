<script lang="ts">
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
	let { children } = $props();
</script>

<div class="auth">
	<header class="top">
		<a href="/" class="brand">Curb <span class="amp">&amp;</span> Co.</a>
		<ThemeToggle />
	</header>
	<main class="card-wrap">
		<article class="card">
			{@render children()}
		</article>
	</main>
</div>

<style>
	.auth {
		min-height: 100vh;
		display: flex;
		flex-direction: column;
	}
	.top {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 18px 24px;
		border-bottom: 1px solid var(--color-rule);
	}
	.brand {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 60, 'SOFT' 30, 'wght' 600;
		font-size: 18px;
		letter-spacing: -0.02em;
		color: var(--color-ink);
		text-decoration: none;
	}
	.amp { color: var(--color-stamp); }
	.card-wrap {
		flex: 1;
		display: grid;
		place-items: center;
		padding: 24px;
	}
	.card {
		width: 100%;
		max-width: 460px;
		background: var(--color-paper-receipt);
		padding: 36px 32px 32px;
		box-shadow: 0 14px 28px -22px rgba(22, 17, 10, 0.18);
		position: relative;
	}
	.card::before, .card::after {
		content: "";
		position: absolute;
		left: 0;
		right: 0;
		height: 8px;
		background: radial-gradient(circle at 4px 8px, var(--color-paper) 3.5px, transparent 4px) 0 0/8px 8px repeat-x;
	}
	.card::before { top: -7px; }
	.card::after { bottom: -7px; transform: scaleY(-1); }
</style>
