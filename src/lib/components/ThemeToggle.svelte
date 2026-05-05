<script lang="ts">
	import { mode, setMode } from 'mode-watcher';
	import { Sun, Moon, Monitor } from 'lucide-svelte';

	function cycle() {
		if (mode.current === 'light') setMode('dark');
		else if (mode.current === 'dark') setMode('system');
		else setMode('light');
	}
</script>

<button
	onclick={cycle}
	class="rounded-md p-2 text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800"
	aria-label="toggle theme"
>
	{#if mode.current === 'light'}
		<Sun class="h-4 w-4" />
	{:else if mode.current === 'dark'}
		<Moon class="h-4 w-4" />
	{:else}
		<Monitor class="h-4 w-4" />
	{/if}
</button>
