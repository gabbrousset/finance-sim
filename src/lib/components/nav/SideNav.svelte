<script lang="ts">
	import { page } from '$app/state';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
	import type { ComponentType, SvelteComponent } from 'svelte';

	let {
		navItems,
		user
	}: {
		navItems: { href: string; label: string; icon: ComponentType<SvelteComponent> }[];
		user: { id: string; username: string; displayName: string } | null;
	} = $props();

	function isActive(href: string): boolean {
		return page.url.pathname === href || page.url.pathname.startsWith(href + '/');
	}
</script>

<aside
	class="fixed inset-y-0 left-0 z-10 hidden w-56 flex-col border-r border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900 md:flex"
>
	<!-- Brand wordmark -->
	<div class="flex h-14 items-center px-5">
		<span class="text-sm font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
			finance-sim
		</span>
	</div>

	<!-- Nav links -->
	<nav class="flex-1 overflow-y-auto px-3 py-2">
		<ul class="space-y-0.5">
			{#each navItems as item}
				{@const active = isActive(item.href)}
				<li>
					<a
						href={item.href}
						class="flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors
							{active
							? 'bg-zinc-100 font-medium text-zinc-900 dark:bg-zinc-800 dark:text-zinc-100'
							: 'text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800/50 dark:hover:text-zinc-100'}"
					>
						<item.icon class="h-4 w-4 shrink-0" />
						{item.label}
					</a>
				</li>
			{/each}
		</ul>
	</nav>

	<!-- Bottom: user info + theme toggle + sign out -->
	<div class="border-t border-zinc-200 p-3 dark:border-zinc-800">
		{#if user}
			<div class="mb-2 truncate px-1 text-xs text-zinc-500 dark:text-zinc-500">
				{user.displayName}
			</div>
		{/if}
		<div class="flex items-center justify-between">
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
	</div>
</aside>
