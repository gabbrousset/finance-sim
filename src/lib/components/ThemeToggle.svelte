<script lang="ts">
	import { mode, setMode } from 'mode-watcher';
	import { Sun, Moon } from 'lucide-svelte';

	// Binary toggle: light ↔ dark. Initial paint follows OS prefs via
	// mode-watcher; explicit toggle from there is binary.
	function toggle() {
		setMode(mode.current === 'dark' ? 'light' : 'dark');
	}
</script>

<button onclick={toggle} class="tt" aria-label="toggle theme">
	{#if mode.current === 'dark'}<Sun class="ico" />
	{:else}<Moon class="ico" />
	{/if}
</button>

<style>
	.tt {
		background: transparent;
		border: 0;
		padding: 6px;
		color: var(--color-ink-2);
		cursor: pointer;
		transition: color 0.15s;
	}
	.tt:hover { color: var(--color-ink); }
	:global(.tt .ico) { width: 16px; height: 16px; }
</style>
