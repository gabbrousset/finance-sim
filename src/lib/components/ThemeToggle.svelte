<script lang="ts">
	import { mode, setMode } from 'mode-watcher';
	import { Sun, Moon, Monitor } from 'lucide-svelte';

	function cycle() {
		if (mode.current === 'light') setMode('dark');
		else if (mode.current === 'dark') setMode('system');
		else setMode('light');
	}
</script>

<button onclick={cycle} class="tt" aria-label="toggle theme">
	{#if mode.current === 'light'}<Sun class="ico" />
	{:else if mode.current === 'dark'}<Moon class="ico" />
	{:else}<Monitor class="ico" />
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
