<script lang="ts">
	import AppShell from '$lib/components/nav/AppShell.svelte';

	let {
		data,
		children
	}: {
		data: {
			user: { id: string; username: string; displayName: string } | null;
			editionNo: number;
		};
		children: import('svelte').Snippet;
	} = $props();
</script>

<AppShell user={data.user} editionNo={data.editionNo}>
	<div class="page">
		{@render children()}
	</div>
</AppShell>

<style>
	.page {
		max-width: 1100px;
		margin: 0 auto;
		padding: 32px clamp(20px, 4vw, 56px) 80px;
	}
</style>
