<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { ComponentType, SvelteComponent } from 'svelte';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
	import SideNav from './SideNav.svelte';
	import MobileTabBar from './MobileTabBar.svelte';
	import { Wallet, ArrowLeftRight, Search, History, Trophy, Settings } from 'lucide-svelte';

	let {
		user,
		children
	}: {
		user: { id: string; username: string; displayName: string } | null;
		children: Snippet;
	} = $props();

	const navItems: { href: string; label: string; icon: ComponentType<SvelteComponent> }[] = [
		{ href: '/portfolio', label: 'Portfolio', icon: Wallet },
		{ href: '/trade', label: 'Trade', icon: ArrowLeftRight },
		{ href: '/quote', label: 'Quote', icon: Search },
		{ href: '/history', label: 'History', icon: History },
		{ href: '/competitions', label: 'Competitions', icon: Trophy },
		{ href: '/settings', label: 'Settings', icon: Settings }
	];
</script>

<!-- Mobile: top header + main + bottom tab bar -->
<div class="flex h-screen flex-col md:flex-row">
	<!-- Mobile top header (hidden on md+) -->
	<header
		class="flex items-center justify-between border-b border-zinc-200 bg-white px-4 py-3 dark:border-zinc-800 dark:bg-zinc-900 md:hidden"
	>
		<span class="text-sm font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
			finance-sim
		</span>
		<div class="flex items-center gap-1">
			<ThemeToggle />
			<form method="POST" action="/signout">
				<button
					type="submit"
					class="rounded-md px-2 py-1 text-xs text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
				>
					Sign out
				</button>
			</form>
		</div>
	</header>

	<!-- Desktop side rail (hidden below md) -->
	<SideNav {navItems} {user} />

	<!-- Main content -->
	<main
		class="flex-1 overflow-y-auto bg-zinc-50 pb-16 dark:bg-zinc-950 md:ml-56 md:pb-0"
	>
		{@render children()}
	</main>

	<!-- Mobile bottom tab bar (hidden on md+) -->
	<MobileTabBar {navItems} />
</div>
