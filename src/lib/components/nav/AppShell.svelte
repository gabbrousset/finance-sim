<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { ComponentType, SvelteComponent } from 'svelte';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
	import SideNav from './SideNav.svelte';
	import MobileTabBar from './MobileTabBar.svelte';
	import TickerTape from './TickerTape.svelte';
	import { Wallet, ArrowLeftRight, Search, History, Trophy, Settings } from 'lucide-svelte';

	let {
		user,
		editionNo = 1,
		ticker = [],
		children
	}: {
		user: { id: string; username: string; displayName: string } | null;
		editionNo?: number;
		ticker?: { symbol: string; price: string; pct: number }[];
		children: Snippet;
	} = $props();

	const navItems: { href: string; label: string; icon: ComponentType<SvelteComponent> }[] = [
		{ href: '/portfolio', label: 'Portfolio', icon: Wallet },
		{ href: '/trade', label: 'Trade', icon: ArrowLeftRight },
		{ href: '/quote', label: 'Quote', icon: Search },
		{ href: '/history', label: 'Ledger', icon: History },
		{ href: '/competitions', label: 'Competitions', icon: Trophy },
		{ href: '/settings', label: 'Settings', icon: Settings }
	];
</script>

<TickerTape ticks={ticker} />

<div class="shell">
	<header class="mobile-top">
		<span class="brand">Curb <span class="amp">&amp;</span> Co.</span>
		<div class="row">
			<ThemeToggle />
			<form method="POST" action="/signout">
				<button type="submit" class="signout">Sign out</button>
			</form>
		</div>
	</header>

	<SideNav {navItems} {user} {editionNo} />

	<main class="main">
		{@render children()}
	</main>

	<MobileTabBar {navItems} />
</div>

<style>
	.shell { min-height: 100vh; }

	.mobile-top {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 14px;
		background: var(--color-paper-2);
		border-bottom: 1px solid var(--color-rule);
	}
	@media (min-width: 768px) {
		.mobile-top { display: none; }
	}
	.brand {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 60, 'SOFT' 30, 'wght' 600;
		font-size: 16px;
		letter-spacing: -0.02em;
		color: var(--color-ink);
	}
	.amp { color: var(--color-stamp); }
	.row { display: flex; align-items: center; gap: 6px; }
	.signout {
		background: transparent;
		border: 0;
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--color-ink-2);
		padding: 4px 6px;
		cursor: pointer;
	}

	.main {
		padding-bottom: 72px;
	}
	@media (min-width: 768px) {
		.main { margin-left: 220px; padding-bottom: 0; }
	}
</style>
