<script lang="ts">
	import { page } from '$app/state';
	import type { ComponentType, SvelteComponent } from 'svelte';

	let {
		navItems
	}: {
		navItems: { href: string; label: string; icon: ComponentType<SvelteComponent> }[];
	} = $props();

	function isActive(href: string): boolean {
		return page.url.pathname === href || page.url.pathname.startsWith(href + '/');
	}

	// Show only the first 5 items in the bottom bar to avoid overflow
	const tabItems = $derived(navItems.slice(0, 5));
</script>

<nav
	class="fixed inset-x-0 bottom-0 z-10 flex border-t border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900 md:hidden"
>
	{#each tabItems as item}
		{@const active = isActive(item.href)}
		<a
			href={item.href}
			class="flex flex-1 flex-col items-center gap-0.5 py-2 text-[10px] transition-colors
				{active
				? 'text-zinc-900 dark:text-zinc-100'
				: 'text-zinc-500 hover:text-zinc-700 dark:text-zinc-500 dark:hover:text-zinc-300'}"
		>
			<item.icon class="h-5 w-5" />
			{item.label}
		</a>
	{/each}
</nav>
