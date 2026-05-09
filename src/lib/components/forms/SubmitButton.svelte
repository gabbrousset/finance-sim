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

<Button type="submit" variant="primary" disabled={disabled || loading}>
	{#if loading}<span class="dot"></span>{/if}
	{@render children()}
</Button>

<style>
	.dot {
		display: inline-block;
		width: 6px; height: 6px;
		background: currentColor;
		border-radius: 50%;
		margin-right: 8px;
		animation: pulse 0.9s ease-in-out infinite;
	}
	@keyframes pulse { 50% { opacity: 0.35; } }
	@media (prefers-reduced-motion: reduce) { .dot { animation: none; } }
</style>
