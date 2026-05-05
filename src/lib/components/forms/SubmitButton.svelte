<script lang="ts">
	import type { Snippet } from 'svelte';
	import Button from '$lib/components/Button.svelte';

	let {
		loading = false,
		disabled = false,
		children
	}: {
		loading?: boolean;
		disabled?: boolean;
		children: Snippet;
	} = $props();
</script>

<Button type="submit" disabled={disabled || loading}>
	{#if loading}
		<svg
			class="mr-2 h-4 w-4 animate-spin"
			fill="none"
			viewBox="0 0 24 24"
			aria-hidden="true"
		>
			<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
			<path
				class="opacity-75"
				fill="currentColor"
				d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
			/>
		</svg>
	{/if}
	{@render children()}
</Button>
