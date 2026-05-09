<script lang="ts">
	let { message = '' }: { message?: string } = $props();
</script>

{#if message}
	<p class="fe" role="alert">{message}</p>
{/if}

<style>
	.fe {
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--color-loss);
		margin: 0;
		padding: 6px 0;
		letter-spacing: 0.02em;
	}
</style>
