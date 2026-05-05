<script lang="ts">
	let { message = '' }: { message?: string } = $props();
</script>

{#if message}
	<div
		class="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-400"
		role="alert"
	>
		<svg
			class="h-4 w-4 shrink-0"
			fill="none"
			stroke="currentColor"
			stroke-width="2"
			viewBox="0 0 24 24"
			aria-hidden="true"
		>
			<circle cx="12" cy="12" r="10" />
			<line x1="12" y1="8" x2="12" y2="12" />
			<line x1="12" y1="16" x2="12.01" y2="16" />
		</svg>
		{message}
	</div>
{/if}
