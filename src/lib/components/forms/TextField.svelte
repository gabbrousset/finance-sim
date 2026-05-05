<script lang="ts">
	import type { HTMLInputAttributes } from 'svelte/elements';

	type Props = Omit<HTMLInputAttributes, 'value'> & {
		name: string;
		label: string;
		value?: string;
		error?: string;
	};

	let {
		name,
		label,
		value = $bindable(''),
		type = 'text',
		placeholder,
		error,
		disabled,
		...rest
	}: Props = $props();
</script>

<div class="flex flex-col gap-1">
	<label for={name} class="text-sm font-medium text-zinc-700 dark:text-zinc-300">
		{label}
	</label>
	<input
		id={name}
		{name}
		{type}
		{placeholder}
		{disabled}
		bind:value
		class="rounded-md border px-3 py-2 text-sm transition-colors
			{error
			? 'border-red-400 focus:border-red-500 focus:ring-red-500/20'
			: 'border-zinc-300 focus:border-zinc-500 focus:ring-zinc-500/20 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100'}
			focus:outline-none focus:ring-2 disabled:cursor-not-allowed disabled:opacity-50"
		{...rest}
	/>
	{#if error}
		<p class="text-xs text-red-600 dark:text-red-400">{error}</p>
	{/if}
</div>
