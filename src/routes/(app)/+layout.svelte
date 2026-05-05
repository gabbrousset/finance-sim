<script lang="ts">
	import AppShell from '$lib/components/nav/AppShell.svelte';

	let {
		data,
		children
	}: {
		data: { user: { id: string; username: string; displayName: string } | null };
		children: import('svelte').Snippet;
	} = $props();
</script>

<AppShell user={data.user}>
	{@render children()}
</AppShell>
