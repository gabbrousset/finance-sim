<script lang="ts">
	import { page } from '$app/state';
	import ThemeToggle from '$lib/components/ThemeToggle.svelte';
	import type { ComponentType, SvelteComponent } from 'svelte';

	let {
		navItems,
		user,
		editionNo = 1
	}: {
		navItems: { href: string; label: string; icon: ComponentType<SvelteComponent> }[];
		user: { id: string; username: string; displayName: string } | null;
		editionNo?: number;
	} = $props();

	function isActive(href: string): boolean {
		return page.url.pathname === href || page.url.pathname.startsWith(href + '/');
	}

	const ROMAN = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII'];
</script>

<aside class="rail">
	<div class="rail__brand">finance<span class="amp">&amp;</span>sim</div>
	<div class="rail__edition">Vol III · No. {editionNo}</div>
	<hr class="rail__rule" />

	<nav class="rail__nav">
		<ul>
			{#each navItems as item, i}
				{@const active = isActive(item.href)}
				<li class:on={active}>
					<a href={item.href}>
						<span class="num">{ROMAN[i] ?? ''}</span>
						<span class="lbl">{item.label}</span>
						{#if active}<span class="dot" aria-hidden="true"></span>{/if}
					</a>
				</li>
			{/each}
		</ul>
	</nav>

	<div class="rail__foot">
		{#if user}
			<div class="who">{user.displayName || user.username}</div>
		{/if}
		<div class="row">
			<ThemeToggle />
			<form method="POST" action="/signout">
				<button type="submit" class="signout">Sign out</button>
			</form>
		</div>
	</div>
</aside>

<style>
	.rail {
		position: fixed;
		inset-block: 0;
		left: 0;
		z-index: 10;
		width: 220px;
		background:
			linear-gradient(to right, var(--color-paper-2) 0, var(--color-paper-2) 6px, transparent 6px),
			var(--color-paper);
		border-right: 1px solid var(--color-rule);
		box-shadow: inset -3px 0 0 var(--color-rule-soft);
		padding: 28px 22px 18px 24px;
		display: none;
		flex-direction: column;
	}
	@media (min-width: 768px) {
		.rail { display: flex; }
	}

	.rail__brand {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 144, 'SOFT' 30, 'wght' 600;
		font-size: 19px;
		letter-spacing: -0.02em;
		line-height: 1;
	}
	.amp { color: var(--color-stamp); font-style: italic; }
	.rail__edition {
		margin-top: 4px;
		font-family: var(--font-mono);
		font-size: 9.5px;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-3);
	}
	.rail__rule {
		border: 0;
		border-top: 1px solid var(--color-rule);
		margin: 22px 0 14px;
	}

	.rail__nav { flex: 1; }
	.rail__nav ul { list-style: none; padding: 0; margin: 0; }
	.rail__nav li { border-bottom: 1px dotted var(--color-rule-soft); }
	.rail__nav a {
		display: flex;
		align-items: baseline;
		gap: 12px;
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 14, 'SOFT' 0, 'wght' 400;
		font-size: 15px;
		color: var(--color-ink-2);
		padding: 9px 0;
		text-decoration: none;
	}
	.rail__nav a:hover { color: var(--color-ink); }
	.rail__nav li.on a {
		color: var(--color-ink);
		font-variation-settings: 'opsz' 14, 'SOFT' 0, 'wght' 600;
	}
	.rail__nav .num {
		font-family: var(--font-mono);
		font-size: 9px;
		letter-spacing: 0.08em;
		color: var(--color-ink-3);
		width: 22px;
		text-align: right;
	}
	.rail__nav li.on .num { color: var(--color-stamp); }
	.rail__nav .dot {
		margin-left: auto;
		width: 5px;
		height: 5px;
		background: var(--color-stamp);
		border-radius: 50%;
		align-self: center;
	}

	.rail__foot {
		margin-top: 14px;
		padding-top: 14px;
		border-top: 1px solid var(--color-rule);
	}
	.rail__foot .who {
		font-family: var(--font-body);
		font-size: 13px;
		color: var(--color-ink);
		margin-bottom: 6px;
	}
	.rail__foot .row {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}
	.signout {
		background: transparent;
		border: 0;
		cursor: pointer;
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--color-ink-2);
		padding: 4px;
	}
	.signout:hover { color: var(--color-stamp); }
</style>
