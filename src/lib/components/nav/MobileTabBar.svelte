<script lang="ts">
	import { page } from '$app/state';
	import type { ComponentType, SvelteComponent } from 'svelte';

	let { navItems }: {
		navItems: { href: string; label: string; icon: ComponentType<SvelteComponent> }[];
	} = $props();

	function isActive(href: string): boolean {
		return page.url.pathname === href || page.url.pathname.startsWith(href + '/');
	}

	const tabs = $derived(navItems.slice(0, 5));
</script>

<nav class="tabbar">
	{#each tabs as item}
		{@const active = isActive(item.href)}
		<a href={item.href} class:on={active}>
			<item.icon class="ico" />
			<span class="lbl">{item.label}</span>
		</a>
	{/each}
</nav>

<style>
	.tabbar {
		position: fixed;
		inset-inline: 0;
		bottom: 0;
		z-index: 10;
		display: flex;
		background: var(--color-paper-2);
		border-top: 1px solid var(--color-rule);
	}
	@media (min-width: 768px) {
		.tabbar { display: none; }
	}
	.tabbar a {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 2px;
		padding: 8px 4px;
		color: var(--color-ink-3);
		text-decoration: none;
	}
	.tabbar a.on { color: var(--color-ink); }
	:global(.tabbar .ico) { width: 18px; height: 18px; }
	.tabbar .lbl {
		font-family: var(--font-mono);
		font-size: 9px;
		letter-spacing: 0.1em;
		text-transform: uppercase;
	}
	.tabbar a.on .lbl { color: var(--color-stamp); }
</style>
